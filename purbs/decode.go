package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"

	"github.com/dedis/kyber"
)

func PURBDecode(data []byte, recipient *Recipient, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE, simplifiedEntryPointTable bool, infoMap SuiteInfoMap) (bool, []byte, error) {
	suiteName := recipient.SuiteName
	suiteInfo := infoMap[suiteName]

	if suiteInfo == nil {
		return false, nil, errors.New("no positions suiteInfo for this suite")
	}

	// XOR all the possible suite positions to computer the cornerstone value
	cornerstone := make([]byte, suiteInfo.KeyLen)
	for _, startPos := range suiteInfo.AllowedPositions {
		endPos := startPos + suiteInfo.KeyLen
		if startPos > len(data) {
			if startPos > len(data) {
				break
			} else {
				endPos = len(data)
			}
		}
		cornerstoneBytes := data[startPos:endPos]
		for j := range cornerstoneBytes {
			cornerstone[j] ^= cornerstoneBytes[j]
		}
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

	// Now we try to decrypt iteratively the entrypoints and check if the decrypted PayloadKey works for AEAD of payload
	if !simplifiedEntryPointTable {
		return entrypointTrialDecode(data, recipient, sharedSecret, suiteInfo, symmKeyWrapType)
	} else {
		return entrypointTrialDecodeSimplified(data, recipient, sharedSecret, suiteInfo, symmKeyWrapType)
	}

	return false, nil, nil
}

func entrypointTrialDecode(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE) (bool, []byte, error){
	var message []byte

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
	hashTableStartPos := suiteInfo.AllowedPositions[0] + suiteInfo.KeyLen
	found := false

	for {
		var entrypointIndexInHashTable int

		// try each position, and up to HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS later
		for j := 0; j < HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS; j++ {
			entrypointIndexInHashTable = (intOfHashedValue + j) % tableSize

			entrypointStartPos := hashTableStartPos + entrypointIndexInHashTable* entrypointLength
			entrypointEndPos := hashTableStartPos + (entrypointIndexInHashTable+1) * entrypointLength

			if entrypointEndPos > len(data) {
				// we're outside the hash table (even outside the blob!), so this j isn't valid
				break
			}

			switch symmKeyWrapType {
				case STREAM:
					xof := recipient.Suite.XOF(sharedSecret)
					decrypted := make([]byte, entrypointLength)
					xof.XORKeyStream(decrypted, data[entrypointStartPos:entrypointEndPos])
					found, message = verifyDecryption(decrypted, data)
				case AEAD:
					panic("not implemented")
			}

			if found {
				return found, message, nil
			}
		}

		hashTableStartPos += tableSize * entrypointLength
		entrypointEndPos := hashTableStartPos + entrypointIndexInHashTable * entrypointLength + entrypointLength
		tableSize *= 2

		if entrypointEndPos > len(data) {
			// we're outside the hash table (even outside the blob!), so we should have decoded the entrypoint before
			return false, nil, errors.New("no entrypoint was correctly decrypted")
		}
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func entrypointTrialDecodeSimplified(data []byte, recipient *Recipient, sharedSecret []byte, suiteInfo *SuiteInfo, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE) (bool, []byte, error){
	var message []byte
	startPos := suiteInfo.AllowedPositions[0] + suiteInfo.KeyLen
	found := false

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
				found, message = verifyDecryption(decrypted, data)
			case AEAD:
				panic("not implemented")
		}
		if found {
			return found, message, nil
		}
		startPos += entrypointLength
	}

	return false, nil, errors.New("no entrypoint was correctly decrypted")
}

func verifyDecryption(entrypoint []byte, fullPURBBlob []byte) (bool, []byte) {
	var result bool

	// verify pointer to payload
	msgStartBytes := entrypoint[SYMMETRIC_KEY_LENGTH : SYMMETRIC_KEY_LENGTH+OFFSET_POINTER_LEN]
	msgStart := int(binary.BigEndian.Uint32(msgStartBytes))
	if msgStart > len(fullPURBBlob) {
		// the pointer is pointing outside the blob
		return false, nil
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
		return false, nil
	}

	if len(msg) != 0 {
		msg = UnPad(msg)
		return result, msg
	} else {
		return result, nil
	}
}
