package purb

import (
	"gopkg.in/dedis/crypto.v0/cipher"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"math"
	"log"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/cipher/aes"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/abstract"
)

//Length each cornerstone value has (for simplicity assuming all suites HideLen is the same).
const KEYLEN = 32

//Length of an entrypoint including encrypted key and location of payload start (16+8 bytes),
//and an authentication tag (16 bytes).
const ENTRYLEN = 40

//Change this value to see if it can give nicer numbers
//--Trade off between header size and decryption time.
const HASHATTEMPTS = 5

// Maximum number of supported cipher suites
const MAXSUITS = 3

// New entrypoint for a given recipient.
func NewEntry(dec Decoder, data []byte) *Entry {
	return &Entry{
		Recipient:    dec,
		Data:         data,
		SharedSecret: nil,
		//HeaderPosition: -1,
	}
}

// New empty Header with initialized maps.
func NewEmptyHeader() *Header {
	s2k := make(map[string]*Cornerstone)
	return &Header{
		Entries:             nil,
		SuitesToCornerstone: s2k,
		layout:              nil,
	}
}

func NewPurb(head *Header, payload []byte) *Purb {
	return &Purb{
		Header: head,
		Payload: payload,
		EncPayloads: make([]EncPayload, 0),
		//buf: make([]byte, 0),
	}
}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) GenCornerstones(rand cipher.Stream) error {
	for _, e := range h.Entries {
		var pair *config.KeyPair
		var encode []byte
		if _, ok := h.SuitesToCornerstone[e.Recipient.Suite.String()]; !ok {
			for {
				// Generate a fresh key pair of a  sprivate key (scalar) and a public key (point)
				pair = config.NewKeyPair(e.Recipient.Suite)
				encode = pair.Public.(abstract.Hiding).HideEncode(rand)
				if pair.Secret != nil && pair.Public != nil {
					if encode != nil {
						break
					}
				} else {
					return errors.New("generated private or public keys were nil")
				}
			}
			padpub := append(encode, random.Bytes(ENTRYLEN - len(encode), rand)...)
			//log.Printf("Length of encoded and padded public key for suite %s is: %d", e.Recipient.Suite.String(), len(padpub))
			h.SuitesToCornerstone[e.Recipient.Suite.String()] = &Cornerstone{priv: pair.Secret, pub: pair.Public, encoded: padpub,}
		}
	}
	return nil
}

// Compute a shared secret per entrypoint used to encrypt it.
// It takes a public key of a recipient and multiplies it by fresh
// private key for a given cipher suite.
func (h *Header) ComputeSharedSecrets() error {
	for _, e := range h.Entries {
		skey, ok := h.SuitesToCornerstone[e.Recipient.Suite.String()]
		if ok {
			sharedKey := e.Recipient.Suite.Point().Mul(e.Recipient.PublicKey, skey.priv) // Compute shared DH key
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

// Create necessary number of hash tables for the layout of the header.
// Number of entries is rounded up to the nearest power of 2 to (the number of cornerstones
// + the number of entrypoints).
func (h *Header) GenHashTables() {
	var headerEntries int
	dataValues := len(h.SuitesToCornerstone) + len(h.Entries)
	for i := 0; headerEntries < dataValues; i++ {
		headerEntries += int(math.Pow(2, float64(i)))
	}
	h.layout = make([][]byte, headerEntries)
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (h *Header) WriteCornerstones(suiteInfo SuiteInfoMap) error {
		for suite, key := range h.SuitesToCornerstone { // for each cornerstone
			info := suiteInfo[suite]
			if info != nil {
				for _, bytepos := range info.Positions {
					if h.layout[bytepos/KEYLEN] == nil {
						h.layout[bytepos/KEYLEN] = key.encoded
						continue
					}
				}
				log.Println("Could not find a position for cornerstone of suite ", suite)
				return errors.New("could not find a free position for a cornerstone")
			} else {
				return errors.New("we do not have info about the needed suite ")
			}
		}
	return nil
}

func (h *Header) WriteEntrypoints() error {
	//for _, entry := range h.Entries {
	//
	//}
	return nil
}

// Prepare initializes a header and places cornerstones. Return a size of future header in bytes
func (h *Header) Prepare(decoders []Decoder, info SuiteInfoMap, rand cipher.Stream) {
	// Add recipients to the header
	for _, d := range decoders {
		h.Entries = append(h.Entries, NewEntry(d, nil))
	}
	if err := h.GenCornerstones(rand); err != nil {
		panic(err)
	}
	if err := h.ComputeSharedSecrets(); err != nil {
		panic(err)
	}
	h.GenHashTables()
	if err := h.WriteCornerstones(info); err != nil {
		panic(err)
	}
}

// Computes the size of a header by simply multiplying the number of allocated byte slices by entrypoint length
func (h *Header) Size() int {
	return len(h.layout) * ENTRYLEN
}

// Write the header into the slice of bytes
func (h *Header) Write(rand cipher.Stream) []byte {
	return nil
}

// Encrypt the payload of the purb using freshly generated symmetric keys and AEAD.
// Payload is encrypted as many times as there are distinct cornerstone values (corresponding cipher suites used).
func (p *Purb) EncryptPayload(rand cipher.Stream) {
	for suite := range p.Header.SuitesToCornerstone {
		// Generate a random 16-byte key and create a cipher from it
		key := random.Bytes(16, rand)
		aead := cipher.NewAEAD(aes.NewCipher128(key))
		// Encrypt and authenticate payload
		enc := make([]byte, 0)
		enc = aead.Seal(enc, key, p.Payload, nil) // additional data is not used in Seal
		p.EncPayloads = append(p.EncPayloads, EncPayload{Suite: suite, Key: key, Content: enc, Size: len(enc)})
	}
}

func MakePurb(payload []byte, decoders []Decoder, si SuiteInfoMap) ([]byte, error) {
	h := NewEmptyHeader()
	h.Prepare(decoders, si, random.Stream)
	purb := NewPurb(h, payload)
	purb.EncryptPayload(random.Stream)
	purb.Header.WriteEntrypoints()

	return nil, nil
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 1, 32, sha256.New)
}

//func (e *Entry) String() string {
//	return fmt.Sprintf("(%s)%p", e.Recipient.Suite, e)
//}
