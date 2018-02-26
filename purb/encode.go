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
	"fmt"
	"syscall"
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
const OFFSET_POINTER_LEN = 4

// Length of a Nonce for AEAD in bytes
const NONCE_LEN = 12

// Lenght of authentication tag
const MAC_LEN = SYMKEYLEN

//Length of an entrypoint including encryption key and location of payload start
//const ENTRYLEN = SYMKEYLEN + OFFSET_POINTER_LEN

// Approaches to wrap a symmetric key
const (
	STREAM = iota
	AEAD
	AES
)

var EXPRM = false

// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
var PLACEMENT_ATTEMPTS = 3

func MakePurb(data []byte, decoders []Decoder, infoMap SuiteInfoMap, keywrap int, simplified bool, stream cipher.Stream) ([]byte, error) {
	// Generate payload key and global nonce. It could be passed by an application above
	key := random.Bytes(SYMKEYLEN, stream)
	nonce := random.Bytes(NONCE_LEN, stream)
	//key := []byte("key16key16key16!")
	//nonce := []byte("noncenonce12")

	purb, err := NewPurb(key, nonce)
	if err != nil {
		return nil, err
	}
	purb.ConstructHeader(decoders, infoMap, keywrap, simplified, stream)
	if err := purb.PadThenEncryptData(data, stream); err != nil {
		return nil, err
	}
	purb.Write(infoMap, keywrap, stream)
	return purb.buf, nil
}

func (p *Purb) ConstructHeader(decoders []Decoder, infoMap SuiteInfoMap, keywrap int, simplified bool, stream cipher.Stream) {
	h := NewEmptyHeader()
	switch keywrap {
	case STREAM:
		h.EntryLen = SYMKEYLEN + OFFSET_POINTER_LEN
	case AEAD:
		h.EntryLen = SYMKEYLEN + OFFSET_POINTER_LEN + MAC_LEN
	}
	m := NewMonitor()
	if err := h.genCornerstones(decoders, infoMap, stream); err != nil {
		panic(err)
	}
	if EXPRM {
		fmt.Printf("%f ", m.RecordAndReset())
	}
	if err := h.computeSharedSecrets(); err != nil {
		panic(err)
	}
	if EXPRM {
		fmt.Printf("%f ", m.Record())
	}
	h.Layout.Reset()
	orderedSuites, err := h.locateCornerstones(infoMap, stream)
	if err != nil {
		panic(err)
	}
	h.locateEntries(infoMap, orderedSuites, simplified, stream)

	p.Header = h
}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) genCornerstones(decoders []Decoder, infoMap SuiteInfoMap, stream cipher.Stream) error {
	for _, dec := range decoders {
		// Add recipients to the header
		if len(h.SuitesToEntries[dec.SuiteName]) == 0 {
			entries := make([]*Entry, 1)
			entries[0] = NewEntry(dec)
			h.SuitesToEntries[dec.SuiteName] = entries
		} else {
			h.SuitesToEntries[dec.SuiteName] = append(h.SuitesToEntries[dec.SuiteName], NewEntry(dec))
		}

		var pair *config.KeyPair
		var encode []byte
		if h.SuitesToCornerstone[dec.SuiteName] == nil {
			for {
				// Generate a fresh key pair of a private key (scalar) and a public key (point)
				pair = config.NewKeyPair(dec.Suite)
				// Elligator encode the public key to a random-looking bit string
				encode = pair.Public.(abstract.Hiding).HideEncode(stream)
				if pair.Secret != nil && pair.Public != nil {
					if encode != nil {
						//log.Printf("Generated public key: %x", encode)
						if len(encode) != infoMap[dec.SuiteName].KeyLen {
							log.Fatal("Length of elligator Encoded key is not what we expect. It's ", len(encode))
						}
						break
					}
				} else {
					return errors.New("generated private or public keys were nil")
				}
			}
			h.SuitesToCornerstone[dec.SuiteName] = &Cornerstone{
				SuiteName: dec.SuiteName,
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
					//h.SuitesToEntries[suite][i].SharedSecret, _ = sharedKey.MarshalBinary()
					//fmt.Printf("Shared secret: %x and length is %d\n", h.SuitesToEntries[suite][i].SharedSecret,
					//	len(h.SuitesToEntries[suite][i].SharedSecret))
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
func (h *Header) locateCornerstones(infoMap SuiteInfoMap, stream cipher.Stream) ([]string, error) {
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
	exclude.Reserve(0, NONCE_LEN, true, "nonce")
	h.Layout.Reserve(0, NONCE_LEN, true, "nonce")

	stones := make([]*Cornerstone, 0)
	for _, stone := range h.SuitesToCornerstone {
		stones = append(stones, stone)
	}
	// Sort the cornerstones such as the ones with the longest key length are placed first.
	// If the lengths are equal, then the sort is lexicographic
	sort.Slice(stones, func(i, j int) bool {
		if len(stones[i].Encoded) > len(stones[j].Encoded) {
			return true
		}
		if len(stones[i].Encoded) == len(stones[j].Encoded) {
			return stones[i].SuiteName < stones[j].SuiteName
		}
		return false
	})
	orderedSuites := make([]string, 0)
	for _, stone := range stones { // for each cornerstone
		info := infoMap[stone.SuiteName]
		orderedSuites = append(orderedSuites, stone.SuiteName)
		if info == nil {
			return nil, errors.New("we do not have info about the needed suite")
		}
		// Reserve all our possible positions in exclude layout,
		// picking the first non-conflicting position as our primary.
		primary := len(info.Positions)
		for j := primary - 1; j >= 0; j-- {
			low := info.Positions[j]
			high := low + info.KeyLen
			if exclude.Reserve(low, high, false, stone.SuiteName) && j == primary-1 {
				//log.Printf("Reserving [%d-%d] for suite %s\n", low, high, stone.SuiteName)
				primary = j // no conflict, shift down
			}
		}
		if primary == len(info.Positions) {
			return nil, errors.New("no viable position for suite " + stone.SuiteName)
		}
		h.SuitesToCornerstone[stone.SuiteName].Offset = info.Positions[primary]

		// Permanently reserve the primary point position in h.Layout
		low, high := info.region(primary)
		if high > h.Length {
			h.Length = high
		}
		//log.Printf("reserving [%d-%d] for suite %s\n", low, high, stone.SuiteName)
		if !h.Layout.Reserve(low, high, true, stone.SuiteName) {
			panic("thought we had that position reserved??")
		}
	}
	return orderedSuites, nil
}

//Function that will find, place and reserve part of the header for the data
//All hash tables start after their cornerstone.
func (h *Header) locateEntries(infoMap SuiteInfoMap, sOrder []string, simplified bool, stream cipher.Stream) {
	for _, suite := range sOrder {
		for i, entry := range h.SuitesToEntries[suite] {
			//hash table start right after the cornerstone's offset-0
			start := infoMap[suite].Positions[0] + infoMap[suite].KeyLen
			if !simplified {
				//initial hash table size
				tableSize := 1
				located := false
				hash := sha256.New()
				hash.Write(entry.SharedSecret)
				absPos := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
				var tHash int
				for {
					for j := 0; j < PLACEMENT_ATTEMPTS; j++ {
						tHash = (absPos + j) % tableSize
						if h.Layout.Reserve(start+tHash*h.EntryLen, start+(tHash+1)*h.EntryLen, true, "hash"+strconv.Itoa(tableSize)) {
							h.SuitesToEntries[suite][i].Offset = start + tHash*h.EntryLen
							located = true
							//log.Printf("Placing entry at [%d-%d]", start+tHash*h.EntryLen, start+(tHash+1)*h.EntryLen)
							break
						}
					}
					if located {
						// save end of the current table as the length of the header
						end := start + (tHash+1)*h.EntryLen
						if end > h.Length {
							h.Length = end
						}
						break
					} else {
						//If we haven't located the entry, update the hash table size and start
						//start = current hash table start + number of entries in the table* the length of each entry
						start += tableSize * h.EntryLen
						tableSize *= 2
					}
				}
			} else { // simplified layout without hash tables
				for {
					if h.Layout.Reserve(start, start+h.EntryLen, true, "hash"+strconv.Itoa(start)) {
						h.SuitesToEntries[suite][i].Offset = start
						end := start + h.EntryLen
						if end > h.Length {
							h.Length = end
						}
						//log.Printf("Placing entry at [%d-%d]", start, start+h.EntryLen)
						break
					} else {
						start += h.EntryLen
					}
				}
			}
		}

	}
}

func (p *Purb) PadThenEncryptData(data []byte, stream cipher.Stream) error {
	var err error
	paddedData := padding.Pad(data, p.Header.Length+MAC_LEN)
	p.Payload, err = AEADEncrypt(paddedData, p.Nonce, p.key, nil, stream)
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Print(paddedData)
	return nil
}

// Write writes content of entrypoints and encrypted payloads into contiguous buffer
func (p *Purb) Write(infoMap SuiteInfoMap, keywrap int, stream cipher.Stream) {
	// copy nonce first
	if len(p.Nonce) != 0 {
		msgbuf := p.growBuf(0, NONCE_LEN)
		copy(msgbuf, p.Nonce)
	}
	//dummy := make([]byte, 0)
	//for i:=0; i<32; i++ {
	//	dummy = append(dummy, 0xFF)
	//}
	// copy cornerstones
	for _, stone := range p.Header.SuitesToCornerstone {
		msgbuf := p.growBuf(stone.Offset, stone.Offset+len(stone.Encoded))
		copy(msgbuf, stone.Encoded)
		//copy(msgbuf, dummy)
	}

	// encrypt and copy entries
	payloadOffset := make([]byte, OFFSET_POINTER_LEN)
	binary.BigEndian.PutUint32(payloadOffset, uint32(p.Header.Length))
	//log.Printf("Payload starts at %d", p.Header.Length)
	entryData := append(p.key, payloadOffset...)
	for _, entries := range p.Header.SuitesToEntries {
		for _, entry := range entries {
			switch keywrap {
			case STREAM:
				// we use shared secret as a seed to a stream cipher
				sec := entry.Recipient.Suite.Cipher(entry.SharedSecret)
				msgbuf := p.growBuf(entry.Offset, entry.Offset+p.Header.EntryLen)
				sec.XORKeyStream(msgbuf, entryData)
			case AEAD:

			}

			//log.Printf("Entry content to place: %x", msgbuf)
		}
	}

	//log.Printf("Buffer with header: %x", p.buf)
	// Fill all unused parts of the header with random bits.
	msglen := len(p.buf)
	//msglen := p.Header.Length
	p.Header.Layout.scanFree(func(lo, hi int) {
		msgbuf := p.growBuf(lo, hi)
		stream.XORKeyStream(msgbuf, msgbuf)
	}, msglen)
	//log.Printf("Final length of header: %d", len(p.buf))
	//log.Printf("Random with header: %x", p.buf)

	// copy message into buffer
	p.buf = append(p.buf, p.Payload...)
	//log.Printf("Buffer with payload: %x", p.buf)

	// XOR each cornerstone with the data in its non-primary positions and save as the cornerstone value
	stones := make([]*Cornerstone, 0)
	for _, stone := range p.Header.SuitesToCornerstone {
		stones = append(stones, stone)
	}
	sort.Slice(stones, func (i, j int) bool {
		return stones[i].Offset < stones[j].Offset
	})
	for _, stone := range stones {
		//log.Println("Write for: ", stone.SuiteName)
		keylen := len(stone.Encoded)
		corbuf := make([]byte, keylen)
		for _, offset := range infoMap[stone.SuiteName].Positions {
			stop := offset + keylen
			// check that we have data at non-primary positions to xor
			if stop > len(p.buf) {
				if offset > len(p.buf) {
					break
				} else {
					stop = len(p.buf)
				}
			}
			tmp := p.buf[offset:stop]
			for b := 0; b < keylen; b++ {
				corbuf[b] ^= tmp[b]
			}
		}
		// copy the result of XOR to the primary position
		copy(p.buf[stone.Offset:stone.Offset+keylen], corbuf)
	}
	//log.Printf("Buffer with xored: %x", p.buf)
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
		return nil, err
	}
	// Encrypt and authenticate payload
	var enc []byte
	enc = aesgcm.Seal(nil, nonce, data, additional) // additional can be nil

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
	high := low + si.KeyLen
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
	if len(nonce) != NONCE_LEN {
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
	return pbkdf2.Key(password, nil, 16, KEYLEN, sha256.New)
}

// Helpers for measurement of CPU cost of operations
type Monitor struct {
	CPUtime float64
}

func NewMonitor() *Monitor {
	var m Monitor
	m.CPUtime = getCPUTime()
	return &m
}

func (m *Monitor) Reset() {
	m.CPUtime = getCPUTime()
}

func (m *Monitor) Record() float64 {
	return getCPUTime() - m.CPUtime
}

func (m *Monitor) RecordAndReset() float64 {
	old := m.CPUtime
	m.CPUtime = getCPUTime()
	return m.CPUtime - old
}

// Returns the sum of the system and the user CPU time used by the current process so far.
func getCPUTime() float64 {
	rusage := &syscall.Rusage{}
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, rusage); err != nil {
		log.Fatalln("Couldn't get rusage time:", err)
		return -1
	}
	s, u := rusage.Stime, rusage.Utime // system and user time
	return iiToF(int64(s.Sec), int64(s.Usec)) + iiToF(int64(u.Sec), int64(u.Usec))
}

// Converts to milliseconds
func iiToF(sec int64, usec int64) float64 {
	return float64(sec)*1000.0 + float64(usec)/1000.0
}