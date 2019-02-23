package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
)

// Decode takes a PURB blob and a recipient info (suite+KeyPair) and extracts the payload
func Decode(data []byte, recipient *Recipient, publicFixedParameters *PurbPublicFixedParameters, verbose bool) (bool, []byte, error) {
	suiteName := recipient.SuiteName
	suiteInfo := publicFixedParameters.SuiteInfoMap[suiteName]

	if verbose {
		log.LLvlf3("Attempting to decode using suite %v, len %v, positions %v", suiteName, suiteInfo.CornerstoneLength, suiteInfo.AllowedPositions)
	}

	if suiteInfo == nil {
		return false, nil, errors.New("no positions suiteInfo for this suite")
	}

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

	//Now that we have the PayloadKey for our suite, calculate the shared PayloadKey
	pubKey := recipient.Suite.Point()
	pubKey.(kyber.Hiding).HideDecode(cornerstone)

	sharedKey := recipient.Suite.Point().Mul(recipient.PrivateKey, pubKey)
	sharedBytes, err := sharedKey.MarshalBinary()
	if err != nil {
		return false, nil, err
	}
	sharedSecret := KDF(sharedBytes)

	if verbose {
		log.LLvlf3("Recovered sharedbytes value %v, len %v", sharedBytes, len(sharedBytes))
		log.LLvlf3("Recovered sharedsecret value %v, len %v", sharedSecret, len(sharedSecret))
	}

	// Now we try to decrypt iteratively the entrypoints and check if the decrypted PayloadKey works for AEAD of payload
	if !publicFixedParameters.SimplifiedEntrypointsPlacement {
		return entrypointTrialDecode(data, recipient, sharedSecret, suiteInfo, publicFixedParameters.HashTableCollisionLinearResolutionAttempts, verbose)
	}
	return entrypointTrialDecodeSimplified(data, recipient, sharedSecret, suiteInfo, verbose)
}

func entrypointTrialDecode(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, hashTableLinearResolutionCollisionAttempt int, verbose bool) (bool, []byte, error) {

	hash := sha256.New()
	hash.Write(sharedSecret)
	intOfHashedValue := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position

	tableSize := 1
	hashTableStartPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

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

			xof := recipient.Suite.XOF(sharedSecret)

			decrypted := make([]byte, suiteInfo.EntryPointLength)
			xof.XORKeyStream(decrypted, data[entrypointStartPos:entrypointEndPos])

			if verbose {
				log.LLvlf3("Recovering potential entrypoint [%v:%v], value %v", entrypointStartPos, entrypointEndPos, data[entrypointStartPos:entrypointEndPos])
				log.LLvlf3("  Attempting decryption with sharedSecret %v", sharedSecret)
				log.LLvlf3("  yield %v", decrypted)
			}

			found, errorReason, message := entrypointTrialDecrypt(decrypted, data)

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

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func entrypointTrialDecodeSimplified(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, verbose bool) (bool, []byte, error) {
	startPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	for startPos+suiteInfo.EntryPointLength < len(data) {
		entrypointBytes := data[startPos : startPos+suiteInfo.EntryPointLength]

		xof := recipient.Suite.XOF(sharedSecret)
		decrypted := make([]byte, suiteInfo.EntryPointLength)
		xof.XORKeyStream(decrypted, entrypointBytes)
		found, errorReason, message := entrypointTrialDecrypt(decrypted, data)

		if verbose {
			log.LLvlf3("  found=%v, reason=%v, decrypted=%v", found, errorReason, message)
		}
		if found {
			return found, message, nil
		}

		startPos += suiteInfo.EntryPointLength
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func entrypointTrialDecrypt(entrypoint []byte, fullPURBBlob []byte) (bool, string, []byte) {

	// verify pointer to payload
	pointerPos := len(entrypoint) - OFFSET_POINTER_LEN
	pointerBytes := entrypoint[pointerPos:]
	pointer := int(binary.BigEndian.Uint32(pointerBytes))
	if pointer > len(fullPURBBlob) {
		// the pointer is pointing outside the blob
		return false, "entrypoint pointer is invalid", nil
	}

	// compute PayloadKey from entrypoint, create the decoder
	key := entrypoint[0:pointerPos]
	payload := fullPURBBlob[pointer:]
	nonce := fullPURBBlob[:AEAD_NONCE_LENGTH]

	msg, err := aeadDecrypt(payload, nonce, key, nil)
	if err != nil {
		return false, "aead opening error", nil
	}

	if len(msg) != 0 {
		msg = unPad(msg)
	}

	return true, "", msg
}

// Decrypt using AEAD
func aeadDecrypt(ciphertext, nonce, key, additional []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt and authenticate payload
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, additional)

	return decrypted, err
}
