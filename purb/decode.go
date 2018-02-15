package purb

import (
	"errors"
	"log"
	"gopkg.in/dedis/crypto.v0/abstract"
	"crypto/sha256"
	"encoding/binary"
	"crypto/aes"
	"crypto/cipher"
	"github.com/nikirill/purbs/padding"
)

func Decode(blob *[]byte, dec *Decoder, infoMap *SuiteInfoMap) (bool, *[]byte, error) {
	suite := dec.Suite
	info := (*infoMap)[suite.String()]
	if info == nil {
		return false, nil, errors.New("no positions info for this suite")
	}
	// XOR all the possible suite positions to computer the cornerstone value
	cornerstone := make([]byte, info.KeyLen)
	for _, offset := range info.Positions {
		stop := offset + info.KeyLen
		if offset > len(*blob) {
			if offset > len(*blob) {
				break
			} else {
				stop = len(*blob)
			}
		}
		temp := (*blob)[offset:stop]
		for j := range temp {
			cornerstone[j] ^= temp[j]
		}
	}

	//Now that we have the key for our suite calculate the shared key
	pub := suite.Point()
	pub.(abstract.Hiding).HideDecode(cornerstone)
	sharedSecret, err := suite.Point().Mul(pub, dec.PrivateKey).MarshalBinary()
	if err != nil {
		return false, nil, err
	}

	// Now we try to decrypt all possible entries and check if the decrypted key works for AEAD of payload
	var message *[]byte
	tableSize := 1
	start := info.Positions[0] + info.KeyLen
	found := false
	hash := sha256.New()
	hash.Write(sharedSecret)
	absPos := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
	var tHash int
	for start+(tHash+1)*ENTRYLEN < len(*blob) {
		for j := 0; j < PLACEMENT_ATTEMPTS; j++ {
			tHash = (absPos + j) % tableSize
			sec := suite.Cipher(sharedSecret)
			decrypted := make([]byte, ENTRYLEN)
			sec.XORKeyStream(decrypted, (*blob)[start+tHash*ENTRYLEN:start+(tHash+1)*ENTRYLEN])
			found, message = verifyDecryption(decrypted, blob)
			if found {
				return found, message, nil
			}
		}
		start += tableSize * ENTRYLEN
		tableSize *= 2
	}

	return false, nil, nil
}

func verifyDecryption(decrypted []byte, blob *[]byte) (bool, *[]byte) {
	msgStart := int(binary.BigEndian.Uint32(decrypted[SYMKEYLEN:SYMKEYLEN+OFFSET_POINTER_SIZE]))
	//log.Println("Start of the message ", msgStart)
	if msgStart > len(*blob) {
		return false, nil
	}
	//log.Println("Key ", decrypted[:SYMKEYLEN])
	key := decrypted[:SYMKEYLEN]
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	msg, err := aesgcm.Open(nil, (*blob)[:NONCE_SIZE], (*blob)[msgStart:], nil)
	if err != nil {
		panic(err.Error())
	}
	if len(msg) != 0 {
		msg = padding.UnPad(msg)
		return true, &msg
	} else {
		return false, nil
	}
}