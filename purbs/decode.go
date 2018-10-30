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

func Decode(blob []byte, dec *Recipient, keywrap SYMMETRIC_KEY_WRAPPER_TYPE, simplified bool, infoMap SuiteInfoMap) (bool, []byte, error) {
	suiteName := dec.SuiteName
	info := infoMap[suiteName]
	if info == nil {
		return false, nil, errors.New("no positions info for this suite")
	}
	var ENTRYLEN int
	switch keywrap {
	case STREAM:
		ENTRYLEN = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		ENTRYLEN = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}
	// XOR all the possible suite positions to computer the cornerstone value
	cornerstone := make([]byte, info.KeyLen)
	for _, offset := range info.AllowedPositions {
		stop := offset + info.KeyLen
		if offset > len(blob) {
			if offset > len(blob) {
				break
			} else {
				stop = len(blob)
			}
		}
		temp := blob[offset:stop]
		for j := range temp {
			cornerstone[j] ^= temp[j]
		}
	}
	//log.Printf("Found the key %x", cornerstone)

	//Now that we have the key for our suite calculate the shared key
	pub := dec.Suite.Point()
	pub.(kyber.Hiding).HideDecode(cornerstone)
	//m := NewMonitor()
	//sharedSecret, err := dec.Suite.Point().Mul(pub, dec.PrivateKey).MarshalBinary()
	sharedBytes, err := dec.Suite.Point().Mul(dec.PrivateKey, pub).MarshalBinary()
	sharedSecret := KDF(sharedBytes)
	//log.Println("Multiplication PURBS: ", m.Record())
	if err != nil {
		return false, nil, err
	}

	// Now we try to decrypt all possible entries and check if the decrypted key works for AEAD of payload
	var message []byte
	start := info.AllowedPositions[0] + info.KeyLen
	found := false
	if !simplified {
		tableSize := 1
		hash := sha256.New()
		hash.Write(sharedSecret)
		absPos := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
		var tHash int
		for start+(tHash+1)*ENTRYLEN < len(blob) {
			for j := 0; j < PLACEMENT_ATTEMPTS; j++ {
				tHash = (absPos + j) % tableSize
				if start+(tHash+1)*ENTRYLEN > len(blob) {
					break
				}
				m := NewMonitor()
				switch keywrap {
				case STREAM:
					xof := dec.Suite.XOF(sharedSecret)
					decrypted := make([]byte, ENTRYLEN)
					xof.XORKeyStream(decrypted, blob[start+tHash*ENTRYLEN:start+(tHash+1)*ENTRYLEN])
					found, message = verifyDecryption(decrypted, blob)
				case AEAD:
				case AES:
				}
				log.Println("EntryPoint point decryption: ", m.Record())

				if found {
					return found, message, nil
				}
			}
			start += tableSize * ENTRYLEN
			tableSize *= 2
		}
	} else {
		for start+ENTRYLEN < len(blob) {
			switch keywrap {
			case STREAM:
				xof := dec.Suite.XOF(sharedSecret)
				decrypted := make([]byte, ENTRYLEN)
				xof.XORKeyStream(decrypted, blob[start:start+ENTRYLEN])
				found, message = verifyDecryption(decrypted, blob)
			case AEAD:
			case AES:
			}
			if found {
				return found, message, nil
			}
			start += ENTRYLEN
		}
	}

	return false, nil, nil
}

func verifyDecryption(decrypted []byte, blob []byte) (bool, []byte) {
	var result bool
	msgStart := int(binary.BigEndian.Uint32(decrypted[SYMMETRIC_KEY_LENGTH : SYMMETRIC_KEY_LENGTH+OFFSET_POINTER_LEN]))
	if msgStart > len(blob) {
		return false, nil
	}
	//log.Println("Start of the message ", msgStart)
	key := decrypted[:SYMMETRIC_KEY_LENGTH]
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	msg, err := aesgcm.Open(nil, blob[:AEAD_NONCE_LENGTH], blob[msgStart:], nil)
	if err == nil {
		result = true
	}
	if len(msg) != 0 {
		msg = UnPad(msg)
		return result, msg
	} else {
		return result, nil
	}
}
