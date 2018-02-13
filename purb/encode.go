package purb

import (
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"log"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/abstract"
	"encoding/binary"
	"crypto/aes"
	"crypto/cipher"
	"github.com/nikirill/purbs/padding"
	"strconv"
	"sort"
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

//Length of an entrypoint including encryption key and location of payload start
const ENTRYLEN = SYMKEYLEN + OFFSET_POINTER_SIZE

// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
const PLACEMENT_ATTEMPTS = 3

func MakePurb(data []byte, decoders []Decoder, si SuiteInfoMap, stream cipher.Stream) (*[]byte, error) {
	// Generate payload key and global nonce. It could be passed by an application above
	key := random.Bytes(KEYLEN, stream)
	nonce := random.Bytes(NONCE_SIZE, stream)

	purb, err := NewPurb(key, nonce)
	if err != nil {
		panic(err.Error())
	}
	purb.ConstructHeader(decoders, &si, stream)
	if err := purb.PadThenEncryptData(&data, stream); err != nil {
		panic(err.Error())
	}
	purb.Write(stream)

	return &purb.buf, nil
}

func (p *Purb) ConstructHeader(decoders []Decoder, info *SuiteInfoMap, stream cipher.Stream) {
	h := NewEmptyHeader()
	if err := h.genCornerstones(&decoders, info, stream); err != nil {
		panic(err)
	}
	if err := h.computeSharedSecrets(); err != nil {
		panic(err)
	}
	h.Layout.Reset()
	orderedSuites, err := h.locateCornerstones(info, stream)
	if err != nil {
		panic(err)
	}
	h.locateEntries(info, orderedSuites, stream)
	//if err := h.fillEntrypoints(p.key, p.Nonce, stream); err != nil {
	//	panic(err)
	//}

	p.Header = h
}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) genCornerstones(decoders *[]Decoder, info *SuiteInfoMap, stream cipher.Stream) error {
	for _, dec := range *decoders {
		// Add recipients to the header
		if len(h.SuitesToEntries[dec.Suite.String()]) == 0 {
			entries := make([]*Entry, 1)
			entries[0] = NewEntry(dec)
			h.SuitesToEntries[dec.Suite.String()] = entries
		} else {
			h.SuitesToEntries[dec.Suite.String()] = append(h.SuitesToEntries[dec.Suite.String()], NewEntry(dec))
		}

		var pair *config.KeyPair
		var encode []byte
		if h.SuitesToCornerstone[dec.Suite.String()] == nil {
			for {
				// Generate a fresh key pair of a private key (scalar) and a public key (point)
				pair = config.NewKeyPair(dec.Suite)
				encode = pair.Public.(abstract.Hiding).HideEncode(stream)
				if pair.Secret != nil && pair.Public != nil {
					if encode != nil {
						log.Printf("Generated public key: %x", encode)
						if len(encode) != (*info)[dec.Suite.String()].KeyLen {
							log.Fatal("Length of elligator Encoded key is not what we expect. It's ", len(encode))
						}
						break
					}
				} else {
					return errors.New("generated private or public keys were nil")
				}
			}
			h.SuitesToCornerstone[dec.Suite.String()] = &Cornerstone{
				SuiteName: dec.Suite.String(),
				Priv:      pair.Secret,
				Pub:       pair.Public,
				Encoded:   encode,
				Offset:    -1,
			}
		}
	}
	return nil
}

// Compute a shared secret per entrypoint used to encrypt it.
// It takes a public key of a recipient and multiplies it by fresh
// private key for a given cipher suite.
func (h *Header) computeSharedSecrets() error {
	for suite, entries := range h.SuitesToEntries {
		for i, e := range entries {
			skey, ok := h.SuitesToCornerstone[suite]
			if ok {
				sharedKey := e.Recipient.Suite.Point().Mul(e.Recipient.PublicKey, skey.Priv) // Compute shared DH key
				if sharedKey != nil {
					sharedBytes, _ := sharedKey.MarshalBinary()
					h.SuitesToEntries[suite][i].SharedSecret = KDF(sharedBytes) // Derive a key using KDF
				} else {
					return errors.New("couldn't negotiate a shared DH key")
				}
			} else {
				return errors.New("no freshly generated private key exists for this ciphersuite")
			}
		}
	}
	return nil
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (h *Header) locateCornerstones(suiteInfo *SuiteInfoMap, stream cipher.Stream) (*[]string, error) {
	// Create two reservation layouts:
	// - In w.layout only each ciphersuite's primary position is reserved.
	// - In exclude we reserve _all_ positions in each ciphersuite.
	// Since the ciphersuites' points will be computed in this same order,
	// each successive ciphersuite's primary position must not overlap
	// any point position for any ciphersuite previously computed,
	// but can overlap positions for ciphersuites to be computed later.
	var exclude SkipLayout
	exclude.Reset()

	// Place a nonce for AEAD first at the beginning of purb
	exclude.Reserve(0, NONCE_SIZE-1, true, "nonce" )
	h.Layout.Reserve(0, NONCE_SIZE-1, true, "nonce" )

	stones := make([]*Cornerstone, 0)
	for _, stone := range h.SuitesToCornerstone {
		stones = append(stones, stone)
	}
	// Sort the cornerstones such as the ones with the longest key length are placed first
	sort.Slice(stones, func(i, j int) bool {
		return len(stones[i].Encoded) > len(stones[j].Encoded)
	})
	orderedSuites := make([]string, 0)
	for _, stone := range stones { // for each cornerstone
		info := (*suiteInfo)[stone.SuiteName]
		orderedSuites = append(orderedSuites, stone.SuiteName)
		if info == nil {
			return nil, errors.New("we do not have info about the needed suite")
		}
		// Reserve all our possible positions in exclude layout,
		// picking the first non-conflicting position as our primary.
		npos := len(info.Positions)
		for j := npos - 1; j >= 0; j-- {
			low := info.Positions[j]
			high := low + info.KeyLen - 1
			//log.Printf("reserving [%d-%d] for suite %s\n", low, high, stone.SuiteName)
			if exclude.Reserve(low, high, false, stone.SuiteName) && j == npos-1 {
				npos = j // no conflict, shift down
			}
		}
		if npos == len(info.Positions) {
			return nil, errors.New("no viable position for suite " + stone.SuiteName)
		}
		h.SuitesToCornerstone[stone.SuiteName].Offset = info.Positions[npos]

		// Permanently reserve the primary point position in h.Layout
		low, high := info.region(npos)
		if high + 1 > h.Length {
			h.Length = high + 1 // +1 because bytes are counted from 0
		}
		log.Printf("reserving [%d-%d] for suite %s\n", low, high, stone.SuiteName)
		if !h.Layout.Reserve(low, high, true, stone.SuiteName) {
			panic("thought we had that position reserved??")
		}
	}
	return &orderedSuites, nil
}

//Function that will find, place and reserve part of the header for the data
//All hash tables start after their cornerstone.
func (h *Header) locateEntries(suiteInfo *SuiteInfoMap, sOrder *[]string, stream cipher.Stream) {
	for _, suite := range *sOrder {
		for i, entry := range h.SuitesToEntries[suite] {
			//initial hash table size
			tableSize := 1
			//hash table start right after the cornerstone
			start := h.SuitesToCornerstone[suite].Offset + (*suiteInfo)[suite].KeyLen
			located := false
			hash := sha256.New()
			hash.Write(entry.SharedSecret)
			absPos := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
			var tHash int
			for {
				for j := 0; j < PLACEMENT_ATTEMPTS; j++ {
					tHash = (absPos + j) % tableSize
					if h.Layout.Reserve(start+tHash*ENTRYLEN, start+(tHash+1)*ENTRYLEN - 1, true, "hash"+strconv.Itoa(tableSize)) {
						h.SuitesToEntries[suite][i].Offset = start + tHash*ENTRYLEN
						located = true
						log.Printf("Placing entry at [%d-%d]", start+tHash*ENTRYLEN, start+(tHash+1)*ENTRYLEN - 1)
						break
					}
				}
				if located {
					// save end of the current table as the length of the header
					end := start+(tHash+1)*ENTRYLEN
					if end > h.Length {
						h.Length = end
					}
					break
				} else {
					//If we haven't located the entry, update the hash table size and start
					//start = current hash table start + number of entries in the table* the length of each entry
					start = start + tableSize*ENTRYLEN
					tableSize *= 2
				}
			}
		}
	}
}

// Write writes content of entrypoints and encrypted payloads into contiguous buffer
func (p *Purb) Write(stream cipher.Stream) {
	// copy nonce first
	if len(p.Nonce) != 0 {
		msgbuf := p.growBuf(0, NONCE_SIZE)
		copy(msgbuf, p.Nonce)
	}
	// copy cornerstones
	for _, corner := range p.Header.SuitesToCornerstone {
		msgbuf := p.growBuf(corner.Offset, corner.Offset + len(corner.Encoded))
		copy(msgbuf, corner.Encoded)
	}

	// encrypt and copy entries
	payloadOffset := make([]byte, OFFSET_POINTER_SIZE)
	binary.BigEndian.PutUint32(payloadOffset, uint32(p.Header.Length))
	entryData := append(p.key, payloadOffset...)
	for _, entries := range p.Header.SuitesToEntries {
		for _, entry := range entries {
			// we use shared secret as a seed to a stream cipher
			cipher := entry.Recipient.Suite.Cipher(entry.SharedSecret)
			msgbuf := p.growBuf(entry.Offset, entry.Offset + ENTRYLEN)
			cipher.XORKeyStream(msgbuf, entryData)
			log.Printf("Entry content to place: %x", msgbuf)
		}
	}

	// Fill all unused parts of the header with random bits.
	msglen := len(p.buf)
	p.Header.Layout.scanFree(func(lo, hi int) {
		msgbuf := p.growBuf(lo, hi)
		stream.XORKeyStream(msgbuf, msgbuf)
	}, msglen)

}

func (p *Purb) PadThenEncryptData(data *[]byte, stream cipher.Stream) error {
	var err error
	paddedData := padding.Pad(data, p.Header.Length + MAC_SIZE)
	p.Payload, err = AEADEncrypt(&paddedData, &p.Nonce, &p.key,nil, stream)
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Print(paddedData)
	return nil
}

// Encrypt the payload of the purb using freshly generated symmetric keys and AEAD.
// Payload is encrypted as many times as there are distinct cornerstone values (corresponding cipher suites used).
func AEADEncrypt(data, nonce, key, additional *[]byte, stream cipher.Stream) ([]byte, error) {
	// Generate a random 16-byte key and create a cipher from it
	if key == nil {
		*key = random.Bytes(KEYLEN, stream)
	}
	block, err := aes.NewCipher(*key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Encrypt and authenticate payload
	var enc []byte
	if additional != nil {
		enc = aesgcm.Seal(nil, *nonce, *data, *additional) // additional can be nil
	} else {
		enc = aesgcm.Seal(nil, *nonce, *data, []byte{}) // additional can be nil
	}

	return enc, nil
}

// Grow the message buffer to include the region from lo to hi,
// and return a slice representing that region.
func (p *Purb) growBuf(lo, hi int) []byte {
	if len(p.buf) < hi {
		b := make([]byte, hi)
		copy(b, p.buf)
		p.buf = b
	}
	return p.buf[lo:hi]
}

// Return the byte-range for a point at a given level.
func (si *SuiteInfo) region(level int) (int, int) {
	low := si.Positions[level]
	high := low + si.KeyLen - 1
	return low, high
}

// New entrypoint for a given recipient.
func NewEntry(dec Decoder) *Entry {
	return &Entry{
		Recipient:    dec,
		SharedSecret: make([]byte, SYMKEYLEN),
		Offset:       -1,
	}
}

// New empty Header with initialized maps.
func NewEmptyHeader() *Header {
	return &Header{
		SuitesToEntries:     make(map[string][]*Entry),
		SuitesToCornerstone: make(map[string]*Cornerstone),
		Length:              0,
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
		Nonce: nonce,
		key:   key,
		buf:   make([]byte, 0),
	}, nil
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 16, SYMKEYLEN, sha256.New)
}

//func (e *Entry) String() string {
//	return fmt.Sprintf("(%s)%p", e.Recipient.Suite, e)
//}
