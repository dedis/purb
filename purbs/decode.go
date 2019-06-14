package purbs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
)

// Decode takes a PURB blob and a recipient info (suite+KeyPair) and extracts the payload
func Decode(blob []byte, recipient *Recipient, publicFixedParameters *PurbPublicFixedParameters, verbose bool) (bool, []byte, error) {
	suiteName := recipient.SuiteName
	suiteInfo := publicFixedParameters.SuiteInfoMap[suiteName]

	if verbose {
		log.LLvlf3("Attempting to decode using suite %v, len %v, positions %v", suiteName, suiteInfo.CornerstoneLength, suiteInfo.AllowedPositions)
	}

	if suiteInfo == nil {
		return false, nil, errors.New("no positions suiteInfo for this suite")
	}

	// we must not take MAC into account when computing public-key XOR
	data := blob[:len(blob)-MAC_AUTHENTICATION_TAG_LENGTH]

	// XOR all the possible suite positions to computer the cornerstone value
	cornerstone := make([]byte, suiteInfo.CornerstoneLength)
	for _, startPos := range suiteInfo.AllowedPositions {
		endPos := startPos + suiteInfo.CornerstoneLength
		if startPos > len(data) {
			if startPos > len(data) {
				break
			} else {
				endPos = len(data)
			}
		}
		if endPos > len(data) {
			endPos = len(data)
		}
		cornerstoneBytes := data[startPos:endPos]

		if verbose {
			log.LLvlf3("XORing in the bytes [%v:%v], value %v", startPos, endPos, cornerstoneBytes)
		}

		for j := range cornerstoneBytes {
			cornerstone[j] ^= cornerstoneBytes[j]
		}
	}

	if verbose {
		log.LLvlf3("Recovered cornerstone has value %v, len %v", cornerstone, len(cornerstone))
	}

	//Now that we have the SessionKey for our suite, calculate the shared SessionKey
	pubKey := recipient.Suite.Point()
	pubKey.(kyber.Hiding).HideDecode(cornerstone)

	sharedKey := recipient.Suite.Point().Mul(recipient.PrivateKey, pubKey)
	sharedBytes, err := sharedKey.MarshalBinary()
	if err != nil {
		return false, nil, err
	}
	sharedSecret := KDF("", sharedBytes)

	if verbose {
		log.LLvlf3("Recovered sharedbytes value %v, len %v", sharedBytes, len(sharedBytes))
		log.LLvlf3("Recovered sharedsecret value %v, len %v", sharedSecret, len(sharedSecret))
	}

	// Now we try to decrypt iteratively the entrypoints and check if the decrypted SessionKey works for AEAD of payload
	if !publicFixedParameters.SimplifiedEntrypointsPlacement {
		return entrypointTrialDecode(blob, recipient, sharedSecret, suiteInfo, publicFixedParameters.HashTableCollisionLinearResolutionAttempts, verbose)
	}
	return entrypointTrialDecodeSimplified(blob, recipient, sharedSecret, suiteInfo, verbose)
}

func entrypointTrialDecode(blob []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, hashTableLinearResolutionCollisionAttempt int, verbose bool) (bool, []byte, error) {

	intOfHashedValue := int(binary.BigEndian.Uint32(KDF("pos", sharedSecret))) // Large number to become a position
	tableSize := 1
	hashTableStartPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	entrypointKey := KDF("key", sharedSecret)
	nonce := blob[:NONCE_LENGTH]
	data := blob[:len(blob)-MAC_AUTHENTICATION_TAG_LENGTH]
	for {
		var entrypointIndexInHashTable int

		// try each position, and up to HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS later
		for j := 0; j < hashTableLinearResolutionCollisionAttempt; j++ {
			entrypointIndexInHashTable = (intOfHashedValue + j) % tableSize

			entrypointStartPos := hashTableStartPos + entrypointIndexInHashTable*suiteInfo.EntryPointLength
			entrypointEndPos := hashTableStartPos + (entrypointIndexInHashTable+1)*suiteInfo.EntryPointLength

			if entrypointEndPos > len(data) {
				// we're outside the hash table (even outside the blob!), so this j isn't valid
				break
			}

			decrypted, err := aeadDecrypt(data[entrypointStartPos:entrypointEndPos], nonce, entrypointKey, nil)
			if err != nil {
				continue // it is not the correct entry point so we move one to try again
			}

			if verbose {
				log.LLvlf3("Recovering potential entrypoint [%v:%v], value %v", entrypointStartPos, entrypointEndPos, data[entrypointStartPos:entrypointEndPos])
				log.LLvlf3("  Attempting decryption with sharedSecret %v", sharedSecret)
				log.LLvlf3("  yield %v", decrypted)
			}

			ok := verifyMAC(decrypted, blob)
			if !ok {
				return false, nil, errors.New("authentication tag is invalid")
			}

			found, errorReason, message := payloadDecrypt(decrypted, data)

			if verbose {
				log.LLvlf3("  found=%v, reason=%v, decrypted=%v", found, errorReason, message)
			}

			if found {
				return found, message, nil
			}
		}

		hashTableStartPos += tableSize * suiteInfo.EntryPointLength
		entrypointEndPos := hashTableStartPos + (entrypointIndexInHashTable+1)*suiteInfo.EntryPointLength
		tableSize *= 2

		if entrypointEndPos > len(data) {
			// we're outside the hash table (even outside the blob!), so we should have decoded the entrypoint before
			return false, nil, errors.New("no entrypoint was correctly decrypted")
		}
	}
}

func entrypointTrialDecodeSimplified(blob []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, verbose bool) (bool, []byte, error) {
	startPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	entrypointKey := KDF("key", sharedSecret)
	nonce := blob[:NONCE_LENGTH]
	data := blob[:len(blob)-MAC_AUTHENTICATION_TAG_LENGTH]
	for startPos+suiteInfo.EntryPointLength < len(data) {
		entrypointBytes := data[startPos : startPos+suiteInfo.EntryPointLength]
		decrypted, err := aeadDecrypt(entrypointBytes, nonce, entrypointKey, nil)
		if err != nil {
			startPos += suiteInfo.EntryPointLength
			continue // it is not the correct entry point so we move one to try again
		}

		ok := verifyMAC(decrypted, blob)
		if !ok {
			return false, nil, errors.New("authentication tag is invalid")
		}

		found, errorReason, message := payloadDecrypt(decrypted, data)

		if verbose {
			log.LLvlf3("  found=%v, reason=%v, decrypted=%v", found, errorReason, message)
		}
		if found {
			return found, message, nil
		}
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

// verifies the authentication tag of a PURB
func verifyMAC(entrypoint []byte, blob []byte) bool {
	sessionKey := entrypoint[0:SYMMETRIC_KEY_LENGTH]
	macKey := KDF("mac", sessionKey)

	data := blob[:len(blob)-MAC_AUTHENTICATION_TAG_LENGTH]
	tag := blob[len(blob)-MAC_AUTHENTICATION_TAG_LENGTH:]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(data)
	computedMAC := mac.Sum(nil)
	return hmac.Equal(computedMAC, tag)
}

func payloadDecrypt(entrypoint []byte, fullPURBBlob []byte) (bool, string, []byte) {
	// verify pointer to payload
	pointerPos := len(entrypoint) - OFFSET_POINTER_LEN
	pointerBytes := entrypoint[pointerPos : pointerPos+OFFSET_POINTER_LEN]
	pointer := int(binary.BigEndian.Uint32(pointerBytes))
	if pointer > len(fullPURBBlob) {
		// the pointer is pointing outside the blob
		return false, "entrypoint pointer is invalid", nil
	}

	// compute SessionKey from entrypoint, create the decoder
	sessionKey := entrypoint[0:pointerPos]
	payload := fullPURBBlob[pointer:]

	key := KDF("enc", sessionKey)
	msg := streamDecrypt(payload, key)

	if len(msg) != 0 {
		msg = unPad(msg)
	}

	return true, "", msg
}
