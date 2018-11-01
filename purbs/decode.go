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

// PURBDecode takes a PURB blob and a recipient info (suite+KeyPair) and extracts the payload
func PURBDecode(data []byte, recipient *Recipient, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE, simplifiedEntryPointTable bool, infoMap SuiteInfoMap, verbose bool) (bool, []byte, error) {
	suiteName := recipient.SuiteName
	suiteInfo := infoMap[suiteName]

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
	if !simplifiedEntryPointTable {
		return entrypointTrialDecode(data, recipient, sharedSecret, suiteInfo, symmKeyWrapType, verbose)
	}
	return entrypointTrialDecodeSimplified(data, recipient, sharedSecret, suiteInfo, symmKeyWrapType, verbose)
}

func entrypointTrialDecode(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE, verbose bool) (bool, []byte, error) {

	var entrypointLength int
	switch symmKeyWrapType {
	case STREAM:
		entrypointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		entrypointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	hash := sha256.New()
	hash.Write(sharedSecret)
	intOfHashedValue := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position

	tableSize := 1
	hashTableStartPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	for {
		var entrypointIndexInHashTable int

		// try each position, and up to HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS later
		for j := 0; j < HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS; j++ {
			entrypointIndexInHashTable = (intOfHashedValue + j) % tableSize

			entrypointStartPos := hashTableStartPos + entrypointIndexInHashTable*entrypointLength
			entrypointEndPos := hashTableStartPos + (entrypointIndexInHashTable+1)*entrypointLength

			if entrypointEndPos > len(data) {
				// we're outside the hash table (even outside the blob!), so this j isn't valid
				break
			}

			switch symmKeyWrapType {
			case STREAM:
				xof := recipient.Suite.XOF(sharedSecret)

				decrypted := make([]byte, entrypointLength)
				xof.XORKeyStream(decrypted, data[entrypointStartPos:entrypointEndPos])

				if verbose {
					log.LLvlf3("Recovering potential entrypoint [%v:%v], value %v", entrypointStartPos, entrypointEndPos, data[entrypointStartPos:entrypointEndPos])
					log.LLvlf3("  Attempting decryption with sharedSecret %v", sharedSecret)
					log.LLvlf3("  yield %v", decrypted)
				}

				found, errorReason, message := verifyDecryption(decrypted, data)

				if verbose {
					log.LLvlf3("  found=%v, reason=%v, decrypted=%v", found, errorReason, message)
				}

				if found {
					return found, message, nil
				}
			case AEAD:
				panic("not implemented")
			}
		}

		hashTableStartPos += tableSize * entrypointLength
		entrypointEndPos := hashTableStartPos + entrypointIndexInHashTable*entrypointLength + entrypointLength
		tableSize *= 2

		if entrypointEndPos > len(data) {
			// we're outside the hash table (even outside the blob!), so we should have decoded the entrypoint before
			return false, nil, errors.New("no entrypoint was correctly decrypted")
		}
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func entrypointTrialDecodeSimplified(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE, verbose bool) (bool, []byte, error) {
	startPos := suiteInfo.AllowedPositions[0] + suiteInfo.CornerstoneLength

	var entrypointLength int
	switch symmKeyWrapType {
	case STREAM:
		entrypointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		entrypointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	for startPos+entrypointLength < len(data) {
		switch symmKeyWrapType {
		case STREAM:
			xof := recipient.Suite.XOF(sharedSecret)
			decrypted := make([]byte, entrypointLength)
			xof.XORKeyStream(decrypted, data[startPos:startPos+entrypointLength])
			found, errorReason, message := verifyDecryption(decrypted, data)

			if verbose {
				log.LLvlf3("  found=%v, reason=%v, decrypted=%v", found, errorReason, message)
			}
			if found {
				return found, message, nil
			}
		case AEAD:
			panic("not implemented")
		}
		startPos += entrypointLength
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func verifyDecryption(entrypoint []byte, fullPURBBlob []byte) (bool, string, []byte) {

	// verify pointer to payload
	msgStartBytes := entrypoint[SYMMETRIC_KEY_LENGTH : SYMMETRIC_KEY_LENGTH+OFFSET_POINTER_LEN]
	msgStart := int(binary.BigEndian.Uint32(msgStartBytes))
	if msgStart > len(fullPURBBlob) {
		// the pointer is pointing outside the blob
		return false, "entrypoint pointer is invalid", nil
	}

	// compute PayloadKey from entrypoint, create the decoder
	key := entrypoint[:SYMMETRIC_KEY_LENGTH]
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}

	// try decoding the payload
	payload := fullPURBBlob[msgStart:]
	aeadNonce := fullPURBBlob[:AEAD_NONCE_LENGTH]

	msg, err := aesgcm.Open(nil, aeadNonce, payload, nil)
	if err != nil {
		return false, "aead opening error", nil
	}

	if len(msg) != 0 {
		msg = unPad(msg)
	}

	return true, "", msg
}
