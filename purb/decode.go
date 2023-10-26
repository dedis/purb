package purb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"purb"

	"go.dedis.ch/kyber/v3"
)

// Decode takes a PURB blob and a recipient info (suite+KeyPair) and extracts the payload
func (p *Purb) Decode(
	blob []byte,
) (bool, []byte, error) {
	suiteName := p.Recipients[0].SuiteName
	suiteInfo := p.config.suiteInfoMap[suiteName]

	purb.Logger.Info().Msgf("Attempting to decode using suite %v, len %v, positions %v",
		suiteName,
		suiteInfo.CornerstoneLength, suiteInfo.AllowedPositions)

	if suiteInfo == nil {
		return false, nil, errors.New("no positions suiteInfo for this suite")
	}

	// XOR all the possible suite positions to computer the cornerstone value
	cornerstone := make([]byte, suiteInfo.CornerstoneLength)
	for _, startPos := range suiteInfo.AllowedPositions {
		endPos := startPos + suiteInfo.CornerstoneLength
		if startPos > len(blob) {
			if startPos > len(blob) {
				break
			}
			endPos = len(blob)
		}
		if endPos > len(blob) {
			endPos = len(blob)
		}
		cornerstoneBytes := blob[startPos:endPos]

		purb.Logger.Debug().Msgf("XORing in the bytes [%v:%v], value %v", startPos, endPos,
			cornerstoneBytes)

		for j := range cornerstoneBytes {
			cornerstone[j] ^= cornerstoneBytes[j]
		}
	}

	purb.Logger.Debug().Msgf("Recovered cornerstone has value %v, len %v", cornerstone,
		len(cornerstone))

	//Now that we have the SessionKey for our suite, calculate the shared SessionKey
	pubKey := p.Recipients[0].Suite.Point()
	pubKey.(kyber.Hiding).HideDecode(cornerstone)

	sharedKey := p.Recipients[0].Suite.Point().Mul(p.Recipients[0].PrivateKey, pubKey)
	sharedBytes, err := sharedKey.MarshalBinary()
	if err != nil {
		return false, nil, err
	}
	sharedSecret := KDF("", sharedBytes)

	purb.Logger.Debug().Msgf("Recovered sharedbytes value %v, len %v", sharedBytes,
		len(sharedBytes))
	purb.Logger.Debug().Msgf("Recovered sharedsecret value %v, len %v", sharedSecret,
		len(sharedSecret))

	// Now we try to decrypt iteratively the entrypoints and check if the decrypted SessionKey works for AEAD of payload
	if !p.config.simplifiedEntrypointsPlacement {
		return entrypointTrialDecode(blob, sharedSecret, suiteInfo,
			p.config.hashTableCollisionLinearResolutionAttempts)
	}
	return entrypointTrialDecodeSimplified(blob, sharedSecret, suiteInfo)
}

func entrypointTrialDecode(
	blob []byte,
	sharedSecret []byte,
	suiteInfo *SuiteInfo,
	hashTableLinearResolutionCollisionAttempt int,
) (bool, []byte, error) {

	intOfHashedValue := int(binary.BigEndian.Uint32(KDF("pos",
		sharedSecret))) // Large number to become a position
	tableSize := 1
	hashTableStartPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	entrypointKey := KDF("key", sharedSecret)
	nonce := blob[:NonceLength]
	data := blob[:len(blob)-MacAuthenticationTagLength]
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

			decrypted, err := aeadDecrypt(data[entrypointStartPos:entrypointEndPos], nonce,
				entrypointKey, nil)
			if err != nil {
				continue // it is not the correct entry point so we move one to try again
			}

			purb.Logger.Debug().Msgf("Recovering potential entrypoint [%v:%v], value %v",
				entrypointStartPos,
				entrypointEndPos, data[entrypointStartPos:entrypointEndPos])
			purb.Logger.Debug().Msgf("  Attempting decryption with sharedSecret %v",
				sharedSecret)
			purb.Logger.Debug().Msgf("  yield %v", decrypted)

			ok := verifyMAC(decrypted, blob)
			if !ok {
				return false, nil, errors.New("authentication tag is invalid")
			}

			found, errorReason, message := payloadDecrypt(decrypted, data)

			purb.Logger.Debug().Msgf("  found=%v, reason=%v, decrypted=%v", found, errorReason,
				message)

			if found {
				return found, message, nil
			}
		}

		hashTableStartPos += tableSize * suiteInfo.EntryPointLength
		entrypointEndPos := hashTableStartPos + (entrypointIndexInHashTable+1)*suiteInfo.EntryPointLength
		tableSize *= 2

		if entrypointEndPos > len(data) {
			// we're outside the hash table (even outside the blob!), so we should have decoded the entrypoint before
			return false, nil, errors.New("no entrypoint was correctly decrypted in normal mode")
		}
	}
}

func entrypointTrialDecodeSimplified(
	blob []byte,
	sharedSecret []byte,
	suiteInfo *SuiteInfo,
) (bool, []byte, error) {
	startPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	entrypointKey := KDF("key", sharedSecret)
	nonce := blob[:NonceLength]
	data := blob[:len(blob)-MacAuthenticationTagLength]
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

		purb.Logger.Debug().Msgf("  found=%v, reason=%v, decrypted=%v",
			found, errorReason, message)
		if found {
			return found, message, nil
		}
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted in simplified mode")
}

// verifies the authentication tag of a PURB
func verifyMAC(entrypoint []byte, blob []byte) bool {
	sessionKey := entrypoint[0:SymmetricKeyLength]
	macKey := KDF("mac", sessionKey)

	data := blob[:len(blob)-MacAuthenticationTagLength]
	tag := blob[len(blob)-MacAuthenticationTagLength:]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(data)
	computedMAC := mac.Sum(nil)
	return hmac.Equal(computedMAC, tag)
}

func payloadDecrypt(entrypoint []byte, fullPURBBlob []byte) (bool, string, []byte) {
	// verify pointers to payload
	startPointerPos := len(entrypoint) - StartOffsetLen - EndOffsetLen
	startPointerBytes := entrypoint[startPointerPos : startPointerPos+StartOffsetLen]
	startPointer := int(binary.BigEndian.Uint32(startPointerBytes))
	endPointerPos := len(entrypoint) - EndOffsetLen
	endPointerBytes := entrypoint[endPointerPos : endPointerPos+EndOffsetLen]
	endPointer := int(binary.BigEndian.Uint32(endPointerBytes))
	if startPointer > len(fullPURBBlob) || endPointer > len(fullPURBBlob) {
		// the pointer is pointing outside the blob
		return false, "either payload start or end pointer is invalid", nil
	}

	// compute SessionKey from entrypoint, create the decoder
	sessionKey := entrypoint[0:startPointerPos]
	payload := unPad(fullPURBBlob[startPointer:], endPointer-startPointer)

	key := KDF("enc", sessionKey)
	msg := streamDecrypt(payload, key)

	return true, "", msg
}
