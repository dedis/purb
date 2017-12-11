package purb

import (
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"math"
	"log"
	"gopkg.in/dedis/crypto.v0/random"
	"crypto/cipher"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/abstract"
	"encoding/binary"
	"crypto/aes"
	"github.com/nikirill/purbs/padding"
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
const AUTH_TAG_LEGTH = SYMKEYLEN

//Length of an entrypoint including encrypted key, location of payload start and payload length (16+4+4 bytes),
//and an authentication tag (16 bytes).
const ENTRYLEN = SYMKEYLEN + OFFSET_POINTER_SIZE + AUTH_TAG_LEGTH

// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
const PLACEMENT_MARGIN = 1

func MakePurb(data []byte, decoders []Decoder, si SuiteInfoMap, stream cipher.Stream) ([]byte, error) {
	var purb *Purb
	// Generate payload key and global nonce. It could be passed by an application above
	key := random.Bytes(KEYLEN, stream)
	nonce := random.Bytes(NONCE_SIZE, stream)
	purb = NewPurb(key, nonce)
	purb.GenerateHeader(decoders, si, stream)

	//encPayload, err := AEADEncrypt(data, purb.Nonce, purb.key,nil, stream)
	//if err != nil {
	//	panic(err)
	//}
	//if err := purb.FillEntrypoints(stream); err != nil {
	//	panic(err)
	//}
	//purb.Write()
	//purb.buf = padding.Pad(purb.buf)

	return nil, nil
}

func (p *Purb) GenerateHeader(decoders []Decoder, info SuiteInfoMap, stream cipher.Stream) {
	h := NewEmptyHeader()
	// Add recipients to the header
	for _, d := range decoders {
		h.Entries = append(h.Entries, NewEntry(d, nil))
	}
	if err := h.GenCornerstones(stream); err != nil {
		panic(err)
	}
	if err := h.ComputeSharedSecrets(); err != nil {
		panic(err)
	}
	h.GenHashTables()
	if err := h.LocateCornerstones(info); err != nil {
		panic(err)
	}


}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) GenCornerstones(stream cipher.Stream) error {
	for _, e := range h.Entries {
		var pair *config.KeyPair
		var encode []byte
		if _, ok := h.SuitesToCornerstone[e.Recipient.Suite.String()]; !ok {
			for {
				// Generate a fresh key pair of a  sprivate key (scalar) and a public key (point)
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
func (h *Header) ComputeSharedSecrets() error {
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
func (h *Header) GenHashTables() {
	var headerEntries int
	dataValues := len(h.SuitesToCornerstone) + len(h.Entries)
	for i := 0; headerEntries < dataValues; i++ {
		headerEntries += int(math.Pow(2, float64(i)))
	}
	h.Layout = make([][]byte, headerEntries)
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (h *Header) LocateCornerstones(suiteInfo SuiteInfoMap) error {
	for suite, key := range h.SuitesToCornerstone { // for each cornerstone
		info := suiteInfo[suite]
		if info != nil {
			for _, bytepos := range info.Positions {
				if h.Layout[bytepos/ENTRYLEN] == nil {
					h.Layout[bytepos/ENTRYLEN] = key.Encoded
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

// Computes the size of a header by simply multiplying the number of allocated byte slices by entrypoint length
func (h *Header) Size() uint32 {
	return uint32(len(h.Layout)) * ENTRYLEN
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

// Encrypt payload keys and offset_start info for each recipient and creates corresponding entrypoints.
// The position of an entrypoint is defined by hashing the shared secret and computing modulo table size.
func (p *Purb) FillEntrypoints(stream cipher.Stream) error {
	for _, entry := range p.Header.Entries {
		var enc []byte
		// Prepare data to place in
		buf := entry.SharedSecret
		// Find and save a starting position of corresponding payload
		var offset, paysize uint32 = 0, 0
		for _, payload := range p.EncPayloads {
			if entry.Recipient.Suite.String() == payload.Suite {
				paysize = payload.Size
				break
			} else {
				offset += payload.Size
			}
		}
		offset += p.Header.Size()
		temp := make([]byte, OFFSET_POINTER_SIZE)
		binary.BigEndian.PutUint32(temp, offset)
		buf = append(buf, temp...)
		if paysize != 0 {
			binary.BigEndian.PutUint32(temp, paysize)
			buf = append(buf, temp...)
		} else {
			return errors.New("payload size turns out to be 0")
		}

		// Encrypting key+offset with AEAD and attaching an auth tag to it
		block, err := aes.NewCipher(entry.SharedSecret)
		if err != nil {
			return err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		stone := p.Header.SuitesToCornerstone[entry.Recipient.Suite.String()]
		if stone != nil {
			enc = aesgcm.Seal(nil, stone.Nonce, buf, nil)
			if len(enc) != ENTRYLEN {
				return errors.New("incorrect length of the encrypted entrypoint")
			}
		} else {
			return errors.New("couldn't retrieve a cornerstone corresponding to this entry")
		}

		// Find a suitable position and write the entrypoint
		hash := sha256.New()
		hash.Write(entry.SharedSecret)
		absPos := binary.BigEndian.Uint32(hash.Sum(nil)) // Large number to become a position for each has table.
		var tableOffset uint32 = 0
		for i := 0; true; i++ {
			tableSize := uint32(math.Pow(2, float64(i)))
			pos := absPos % tableSize
			if tableOffset+pos > uint32(len(p.Header.Layout)) {
				panic("we ran out of hash tables and did not find a suitable position")
				return errors.New("couldn't find a place for an entrypoint")
			}
			for j := 0; j <= PLACEMENT_MARGIN; j++ {
				if p.Header.Layout[tableOffset+pos] == nil {
					p.Header.Layout[tableOffset+pos] = enc
					break
				} else {
					pos = (pos + 1) % tableSize
				}
			}
			// Updating where the current table starts
			tableOffset += tableSize
		}
	}
	// Fill empty unused entries with random bits
	for i, cell := range p.Header.Layout {
		if cell == nil {
			p.Header.Layout[i] = random.Bytes(ENTRYLEN, stream)
		}
	}
	return nil
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

//// Prepare initializes a header and places cornerstones. Return a size of future header in bytes
//func (h *Header) Prepare(decoders []Decoder, info SuiteInfoMap, stream cipher.Stream) {
//	// Add recipients to the header
//	for _, d := range decoders {
//		h.Entries = append(h.Entries, NewEntry(d, nil))
//	}
//	if err := h.GenCornerstones(stream); err != nil {
//		panic(err)
//	}
//	if err := h.ComputeSharedSecrets(); err != nil {
//		panic(err)
//	}
//	h.GenHashTables()
//	if err := h.LocateCornerstones(info); err != nil {
//		panic(err)
//	}
//}

// New entrypoint for a given recipient.
func NewEntry(dec Decoder, data []byte) *Entry {
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

func NewPurb(key []byte, nonce []byte) *Purb {
	return &Purb{
		Nonce:   nonce,
		Header:  nil,
		Payload: nil,
		key:     key,
		buf:     make([]byte, 0),
	}
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 16, SYMKEYLEN, sha256.New)
}

//func (e *Entry) String() string {
//	return fmt.Sprintf("(%s)%p", e.Recipient.Suite, e)
//}
