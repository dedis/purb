package purb

import (
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"math"
	"log"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/abstract"
	"encoding/binary"
	"crypto/aes"
	"crypto/cipher"
	"github.com/nikirill/purbs/padding"
	"fmt"
)

// Cornerstone - 40 bytes
//  ______32____ ___8___
// | Public Key | Nonce |
//  –––––––––––– –––––––
//
// Entrypoint - 40 bytes
//  _______16______ _______4_______ ________4_______ _16__
// | Symmetric Key | Payload Start | Payload Length | MAC |
//  ––––––––––––––– ––––––––––––––– –––––––––––––––– –––––
//
// PURB
//  __12___ ________ ______________
// | Nonce | Header | Payload + MAC|
//  ––––––– –––––––– ––––––––––––––

//Length each cornerstone value has (for simplicity assuming all suites HideLen is the same).
const KEYLEN = 32

// Length of all the symmetric keys
const SYMKEYLEN = 16

// Length of offset pointer
const OFFSET_POINTER_SIZE = 4

// Length of a Nonce for AEAD in bytes
const NONCE_SIZE = 12

// Lenght of authentication tag
const MAC_SIZE = SYMKEYLEN

//Length of an entrypoint including encrypted key, location of payload start and payload length (16+4+4 bytes),
//and an authentication tag (16 bytes).
const ENTRYLEN = SYMKEYLEN + OFFSET_POINTER_SIZE + MAC_SIZE

// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
const PLACEMENT_MARGIN = 3

func MakePurb(data []byte, decoders []Decoder, si SuiteInfoMap, stream cipher.Stream) ([]byte, error) {
	// Generate payload key and global nonce. It could be passed by an application above
	key := random.Bytes(KEYLEN, stream)
	nonce := random.Bytes(NONCE_SIZE, stream)

	purb, err := NewPurb(key, nonce)
	if err != nil {
		panic(err.Error())
	}
	purb.ConstructHeader(decoders, si, stream)
	if err:= purb.PadThenEncryptData(data, stream); err != nil {
		panic(err.Error())
	}
	purb.XORCornerstones(si)

	//encPayload, err := AEADEncrypt(data, purb.Nonce, purb.key,nil, stream)
	//if err != nil {
	//	panic(err)
	//}
	//purb.Write()
	//purb.buf = padding.Pad(purb.buf)

	return nil, nil
}

func (p *Purb) ConstructHeader(decoders []Decoder, info SuiteInfoMap, stream cipher.Stream) {
	h := NewEmptyHeader()
	// Add recipients to the header
	for _, d := range decoders {
		h.Entries = append(h.Entries, NewEntry(d))
	}
	if err := h.genCornerstones(stream); err != nil {
		panic(err)
	}
	if err := h.computeSharedSecrets(); err != nil {
		panic(err)
	}
	h.genHashTables()
	if err := h.locateCornerstones(info, stream); err != nil {
		panic(err)
	}
	if err := h.fillEntrypoints(p.key, p.Nonce, stream); err != nil {
		panic(err)
	}

	p.Header = h
}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) genCornerstones(stream cipher.Stream) error {
	for _, e := range h.Entries {
		var pair *config.KeyPair
		var encode []byte
		if _, ok := h.SuitesToCornerstone[e.Recipient.Suite.String()]; !ok {
			for {
				// Generate a fresh key pair of a private key (scalar) and a public key (point)
				pair = config.NewKeyPair(e.Recipient.Suite)
				encode = pair.Public.(abstract.Hiding).HideEncode(stream)
				if pair.Secret != nil && pair.Public != nil {
					if encode != nil {
						if len(encode) != KEYLEN {
							log.Fatal("Length of elligator Encoded key is not what we expect. It's ", len(encode))
						}
						break
					}
				} else {
					return errors.New("generated private or public keys were nil")
				}
			}
			h.SuitesToCornerstone[e.Recipient.Suite.String()] = &Cornerstone{
				Priv:    pair.Secret,
				Pub:     pair.Public,
				Encoded: encode,
			}
		}
	}
	return nil
}

// Compute a shared secret per entrypoint used to encrypt it.
// It takes a public key of a recipient and multiplies it by fresh
// private key for a given cipher suite.
func (h *Header) computeSharedSecrets() error {
	for _, e := range h.Entries {
		skey, ok := h.SuitesToCornerstone[e.Recipient.Suite.String()]
		if ok {
			sharedKey := e.Recipient.Suite.Point().Mul(e.Recipient.PublicKey, skey.Priv) // Compute shared DH key
			if sharedKey != nil {
				sharedBytes, _ := sharedKey.MarshalBinary()
				e.SharedSecret = KDF(sharedBytes) // Derive a key using KDF
			} else {
				return errors.New("couldn't negotiate a shared DH key")
			}
		} else {
			return errors.New("no freshly generated private key exists for this ciphersuite")
		}
	}
	return nil
}

// Create necessary number of hash tables for the Layout of the header.
// Number of entries is rounded up to the nearest power of 2 to (the number of cornerstones
// + the number of entrypoints).
func (h *Header) genHashTables() {
	var headerEntries int
	power := math.Logb(float64(len(h.SuitesToCornerstone) + len(h.Entries)))
	headerEntries = int(math.Pow(2, float64(power)+1)) - 1
	h.Layout = make([][]byte, headerEntries)
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (h *Header) locateCornerstones(suiteInfo SuiteInfoMap, stream cipher.Stream) error {
	for suite, key := range h.SuitesToCornerstone { // for each cornerstone
		var buf []byte
		info := suiteInfo[suite]
		if info != nil {
			for _, bytepos := range info.Positions {
				if h.Layout[bytepos/ENTRYLEN] == nil {
					// Padding the key so the string length equals the entry length
					buf = key.Encoded
					buf = append(buf, random.Bytes(ENTRYLEN-KEYLEN, stream)...)
					h.Layout[bytepos/ENTRYLEN] = buf
					//log.Printf("Cornestone written to the entry is %x\n", buf)
					break
				}
			}
			if buf == nil {
				return errors.New("could not find a free position for a cornerstone")
			}
		} else {
			return errors.New("we do not have info about the needed suite ")
		}
	}
	return nil
}

// Encrypt the payload key and offset_start info for each recipient and creates corresponding entrypoints.
// The position of an entrypoint is defined by hashing the shared secret and computing modulo table size.
func (h *Header) fillEntrypoints(datakey []byte, gnonce []byte, stream cipher.Stream) error {
	// Find and save a starting position of the payload
	offset := make([]byte, OFFSET_POINTER_SIZE)
	binary.BigEndian.PutUint32(offset, NONCE_SIZE+uint32(h.Size()))
	attemptCounter := 0
	enoughTables := true
	for !enoughTables {
		for _, entry := range h.Entries {
			var enc []byte
			// Prepare data to place in
			buf := datakey
			buf = append(buf, offset...)
			enc, err := AEADEncrypt(buf, gnonce, entry.SharedSecret, nil, stream)
			if err != nil {
				return err
			}
			if len(enc) != ENTRYLEN {
				return errors.New("incorrect length of the encrypted entrypoint")
			}

			// Find a suitable position and write the entrypoint
			hash := sha256.New()
			hash.Write(entry.SharedSecret)
			absPos := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
			var tableOffset = 0
			for i := 0; true; i++ {
				tableSize := int(math.Pow(2, float64(i)))
				pos := absPos % tableSize
				if tableOffset+pos > len(h.Layout)-1 {
					enoughTables = false
					break
				}
				for j := 0; j <= PLACEMENT_MARGIN; j++ {
					if h.Layout[tableOffset+pos] == nil {
						h.Layout[tableOffset+pos] = enc
						break
					} else {
						pos = (pos + 1) % tableSize
					}
				}
				// Updating where the current table starts
				tableOffset += tableSize
			}
			if enoughTables == false {
				// We try to grow the layout twice if there is not space. If it doesn't help, then panic
				if attemptCounter += 1; attemptCounter < 2 {
					addition := make([][]byte, len(h.Layout)+1)
					h.Layout = append(h.Layout, addition...)
					break
				} else {
					panic("we ran out of hash tables and did not find a suitable position")
					return errors.New("couldn't find a place for an entrypoint")
				}
			}
		}
	}
	// Fill empty unused entries with random bits
	for i, cell := range h.Layout {
		if cell == nil {
			h.Layout[i] = random.Bytes(ENTRYLEN, stream)
		}
	}
	return nil
}

// Computes the size of a header by simply multiplying the number of allocated byte slices by entrypoint length
func (h *Header) Size() int {
	return len(h.Layout) * ENTRYLEN
}

func (p *Purb) PadThenEncryptData(data []byte, stream cipher.Stream) error {
	paddedData := padding.Pad(data, NONCE_SIZE + p.Header.Size() + MAC_SIZE)
	fmt.Print(paddedData)
	return nil
}

func (p *Purb) XORCornerstones(si SuiteInfoMap) {
	//for suite, stone := range p.Header.SuitesToCornerstone {
	//	positions := si[suite]
	//}
}

// Encrypt the payload of the purb using freshly generated symmetric keys and AEAD.
// Payload is encrypted as many times as there are distinct cornerstone values (corresponding cipher suites used).
func AEADEncrypt(data, nonce, key, additional []byte, stream cipher.Stream) ([]byte, error) {
	// Generate a random 16-byte key and create a cipher from it
	if key == nil {
		key = random.Bytes(KEYLEN, stream)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Encrypt and authenticate payload
	enc := aesgcm.Seal(nil, nonce, data, additional) // additional can be nil
	return enc, nil
}

//// Write writes content of entrypoints and encrypted payloads into contiguous buffer
//func (p *Purb) Write() {
//	for _, entry := range p.Header.Layout {
//		p.buf = append(p.buf, entry...)
//	}
//	for _, payload := range p.EncPayloads {
//		p.buf = append(p.buf, payload.Content...)
//	}
//}

// New entrypoint for a given recipient.
func NewEntry(dec Decoder) *Entry {
	return &Entry{
		Recipient:    dec,
		SharedSecret: make([]byte, SYMKEYLEN),
	}
}

// New empty Header with initialized maps.
func NewEmptyHeader() *Header {
	s2k := make(map[string]*Cornerstone)
	return &Header{
		Entries:             nil,
		SuitesToCornerstone: s2k,
		Layout:              nil,
	}
}

func NewPurb(key []byte, nonce []byte) (*Purb, error) {
	if len(nonce) != NONCE_SIZE {
		return nil, errors.New("incorrect nonce size")
	}
	if len(key) != SYMKEYLEN {
		return nil, errors.New("incorrect symmetric key size")
	}
	return &Purb{
		Nonce:   nonce,
		Header:  nil,
		Payload: nil,
		key:     key,
		buf:     make([]byte, 0),
	}, nil
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 16, SYMKEYLEN, sha256.New)
}

//func (e *Entry) String() string {
//	return fmt.Sprintf("(%s)%p", e.Recipient.Suite, e)
//}
