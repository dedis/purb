package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"sort"
	"strconv"
	"syscall"

	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
)

const SYMMETRIC_KEY_LENGTH = 16
const OFFSET_POINTER_LEN = 4
const AEAD_NONCE_LENGTH = 12
const MAC_AUTHENTICATION_TAG_LENGTH = SYMMETRIC_KEY_LENGTH
// for simplicity assuming all suites HideLen is the same).
const CORNERSTONE_LENGTH = 32

// Approaches to wrap a symmetric key
type SYMMETRIC_KEY_WRAPPER_TYPE int8
const (
	STREAM SYMMETRIC_KEY_WRAPPER_TYPE = iota
	AEAD
	AES
)


// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
var PLACEMENT_ATTEMPTS = 3

func MakePurb(data []byte, decoders []Recipient, infoMap SuiteInfoMap, keywrap SYMMETRIC_KEY_WRAPPER_TYPE, simplified bool, stream cipher.Stream) ([]byte, error) {
	// Generate payload key and global nonce. It could be passed by an application above
	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, AEAD_NONCE_LENGTH)
	random.Bytes(key, stream)
	random.Bytes(nonce, stream)
	//key := []byte("key16key16key16!")
	//nonce := []byte("noncenonce12")

	purb, err := NewPurb(key, nonce)
	if err != nil {
		return nil, err
	}
	purb.CreateHeader(decoders, infoMap, keywrap, simplified, stream)
	if err := purb.PadThenEncryptData(data, stream); err != nil {
		return nil, err
	}
	purb.Write(infoMap, keywrap, stream)
	return purb.buf, nil
}

func (p *Purb) CreateHeader(recipients []Recipient, infoMap SuiteInfoMap, symmKeyWrapType SYMMETRIC_KEY_WRAPPER_TYPE, simplified bool, stream cipher.Stream) {

	h := NewEmptyHeader()

	switch symmKeyWrapType {
		case STREAM:
			h.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
		case AEAD:
			h.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	h.createCornerStoneAndEntryPoints(recipients, infoMap)
	h.computeSharedSecrets()

	h.Layout.Reset()
	orderedSuites, err := h.placeCornerstones(infoMap, stream)
	if err != nil {
		panic(err)
	}

	h.placeEntrypoints(infoMap, orderedSuites, simplified, stream)

	p.Header = h
}

// Find what unique suites used by the Recipients, generate a private for each of these suites, and assign them to corresponding entry points
func (h *Header) createCornerStoneAndEntryPoints(recipients []Recipient, infoMap SuiteInfoMap) {

	for _, recipient := range recipients {

		// create the entrypoint that will match this cornerstone
		if len(h.EntryPoints[recipient.SuiteName]) == 0 {
			h.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}
		h.EntryPoints[recipient.SuiteName] = append(h.EntryPoints[recipient.SuiteName], NewEntryPoint(recipient))

		// now create the said cornerstone. We skip if we already have a cornerstone for this suite
		if h.Cornerstones[recipient.SuiteName] != nil {
			continue
		}

		var keyPair *key.Pair
		for {
			// Generate a fresh key keyPair of a private key (scalar), a public key (point), and hidden encoding of the public key
			keyPair = key.NewHidingKeyPair(recipient.Suite)

			if keyPair.Private == nil || keyPair.Public == nil {
				continue
			}

			if keyPair.Hiding == nil {
				continue
			}

			if keyPair.Hiding.HideLen() != infoMap[recipient.SuiteName].KeyLen {
				log.Fatal("Length of elligator Encoded key is not what we expect. It's ", keyPair.Hiding.HideLen())
			}

			// key is OK!
			break
		}

		// register a new cornerstone for this suite
		h.Cornerstones[recipient.SuiteName] = &Cornerstone{
			SuiteName: recipient.SuiteName,
			KeyPair:   keyPair,
			Offset:    -1, // we don't know this yet
		}
	}
}

// Compute a shared secret per entrypoint used to encrypt it. It takes a public key of a recipient and multiplies it by fresh private key for a given cipher suite.
func (h *Header) computeSharedSecrets() {

	// for each entrypoint in each suite
	for suiteName, entrypoints := range h.EntryPoints {
		for i, entrypoint := range entrypoints {

			cornerstone, found := h.Cornerstones[suiteName]
			if !found {
				panic("no freshly generated private key exists for this ciphersuite")
			}

			recipientKey := entrypoint.Recipient.PublicKey
			senderKey := cornerstone.KeyPair.Private

			sharedKey := recipientKey.Mul(senderKey, recipientKey) // Compute shared DH key
			if sharedKey == nil {
				panic("couldn't negotiate a shared DH key")
			}

			sharedBytes, err := sharedKey.MarshalBinary()
			if err != nil {
				panic("error" + err.Error())
			}
			// Derive a key using KDF
			h.EntryPoints[suiteName][i].SharedSecret = KDF(sharedBytes)

			//h.EntryPoints[suiteName][i].SharedSecret, _ = sharedKey.MarshalBinary()
			//fmt.Printf("Shared secret: %x and length is %d\n", h.EntryPoints[suiteName][i].SharedSecret,
			//	len(h.EntryPoints[suiteName][i].SharedSecret))
		}
	}
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (h *Header) placeCornerstones(infoMap SuiteInfoMap, stream cipher.Stream) ([]string, error) {
	// Create two reservation layouts:
	// - In w.layout only each ciphersuite's primary position is reserved.
	// - In excludeLayout we reserve _all_ positions in each ciphersuite.
	// Since the ciphersuites' points will be computed in this same order,
	// each successive ciphersuite's primary position must not overlap
	// any point position for any ciphersuite previously computed,
	// but can overlap positions for ciphersuites to be computed later.
	var excludeLayout SkipLayout
	excludeLayout.Reset()

	// Place a nonce for AEAD first at the beginning of purb
	excludeLayout.Reserve(0, AEAD_NONCE_LENGTH, true, "nonce")
	h.Layout.Reserve(0, AEAD_NONCE_LENGTH, true, "nonce")

	// copy all cornerstones
	cornerstones := make([]*Cornerstone, 0)
	for _, cornerstone := range h.Cornerstones {
		cornerstones = append(cornerstones, cornerstone)
	}

	// Sort the cornerstones such as the ones with the longest key length are placed first.
	// If the lengths are equal, then the sort is lexicographic
	sort.Slice(cornerstones, func(i, j int) bool {
		if cornerstones[i].KeyPair.Hiding.HideLen() > cornerstones[j].KeyPair.Hiding.HideLen() {
			return true
		}
		if cornerstones[i].KeyPair.Hiding.HideLen() == cornerstones[j].KeyPair.Hiding.HideLen() {
			return cornerstones[i].SuiteName < cornerstones[j].SuiteName
		}
		return false
	})

	orderedSuites := make([]string, 0)
	for _, cornerstone := range cornerstones {

		suiteInfo := infoMap[cornerstone.SuiteName]
		if suiteInfo == nil {
			return nil, errors.New("we do not have suiteInfo about the needed suite")
		}

		orderedSuites = append(orderedSuites, cornerstone.SuiteName)

		// Reserve all our possible positions in excludeLayout layout,
		// picking the first non-conflicting position as our primary.
		primary := len(suiteInfo.AllowedPositions)
		for j := primary - 1; j >= 0; j-- {

			startPos := suiteInfo.AllowedPositions[j]
			endPos := startPos + suiteInfo.KeyLen
			if excludeLayout.Reserve(startPos, endPos, false, cornerstone.SuiteName) && j == primary-1 {
				//log.Printf("Reserving [%d-%d] for suite %s\n", startPos, endPos, cornerstone.SuiteName)
				primary = j // no conflict, shift down
			}
		}
		if primary == len(suiteInfo.AllowedPositions) {
			return nil, errors.New("no viable position for suite " + cornerstone.SuiteName)
		}
		h.Cornerstones[cornerstone.SuiteName].Offset = suiteInfo.AllowedPositions[primary]

		// Permanently reserve the primary point position in h.Layout
		startBit, endBit := suiteInfo.region(primary)
		if endBit > h.Length {
			h.Length = endBit
		}
		//log.Printf("reserving [%d-%d] for suite %s\n", startBit, endBit, cornerstone.SuiteName)
		if !h.Layout.Reserve(startBit, endBit, true, cornerstone.SuiteName) {
			panic("thought we had that position reserved??")
		}
	}
	return orderedSuites, nil
}

// placeEntrypoints will find, place and reserve part of the header for the data
// All hash tables start after their cornerstone.
func (h *Header) placeEntrypoints(infoMap SuiteInfoMap, orderedSuites []string, simplified bool, stream cipher.Stream) {
	for _, suite := range orderedSuites {
		for i, entry := range h.EntryPoints[suite] {
			//hash table start right after the cornerstone's offset-0
			start := infoMap[suite].AllowedPositions[0] + infoMap[suite].KeyLen
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
						if h.Layout.Reserve(start+tHash*h.EntryPointLength, start+(tHash+1)*h.EntryPointLength, true, "hash"+strconv.Itoa(tableSize)) {
							h.EntryPoints[suite][i].Offset = start + tHash*h.EntryPointLength
							located = true
							//log.Printf("Placing entry at [%d-%d]", start+tHash*h.EntryPointLength, start+(tHash+1)*h.EntryPointLength)
							break
						}
					}
					if located {
						// save end of the current table as the length of the header
						end := start + (tHash+1)*h.EntryPointLength
						if end > h.Length {
							h.Length = end
						}
						break
					} else {
						//If we haven't located the entry, update the hash table size and start
						//start = current hash table start + number of entries in the table* the length of each entry
						start += tableSize * h.EntryPointLength
						tableSize *= 2
					}
				}
			} else { // simplified layout without hash tables
				for {
					if h.Layout.Reserve(start, start+h.EntryPointLength, true, "hash"+strconv.Itoa(start)) {
						h.EntryPoints[suite][i].Offset = start
						end := start + h.EntryPointLength
						if end > h.Length {
							h.Length = end
						}
						//log.Printf("Placing entry at [%d-%d]", start, start+h.EntryPointLength)
						break
					} else {
						start += h.EntryPointLength
					}
				}
			}
		}

	}
}


// placeEntrypoints will find, place and reserve part of the header for the data. Does not use a hash table, put the points linearly
func (h *Header) placeEntrypointsSimplified(infoMap SuiteInfoMap, orderedSuites []string, stream cipher.Stream) {
	for _, suite := range orderedSuites {
		for i := range h.EntryPoints[suite] {
			//hash table start right after the cornerstone's offset-0
			start := infoMap[suite].AllowedPositions[0] + infoMap[suite].KeyLen

			//TODO: Resume here

			for {
				if h.Layout.Reserve(start, start+h.EntryPointLength, true, "hash"+strconv.Itoa(start)) {
					h.EntryPoints[suite][i].Offset = start
					end := start + h.EntryPointLength
					if end > h.Length {
						h.Length = end
					}
					//log.Printf("Placing entry at [%d-%d]", start, start+h.EntryPointLength)
					break
				} else {
					start += h.EntryPointLength
				}
			}
		}

	}
}

// PadThenEncryptData takes plaintext data as a byte slice, pads it using PURBs padding scheme,
// and then encrypts using AEAD encryption scheme
func (p *Purb) PadThenEncryptData(data []byte, stream cipher.Stream) error {
	var err error
	paddedData := Pad(data, p.Header.Length+MAC_AUTHENTICATION_TAG_LENGTH)
	p.Payload, err = AEADEncrypt(paddedData, p.Nonce, p.key, nil, stream)
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Print(paddedData)
	return nil
}

// Write writes content of entrypoints and encrypted payloads into contiguous buffer
func (p *Purb) Write(infoMap SuiteInfoMap, keywrap SYMMETRIC_KEY_WRAPPER_TYPE, stream cipher.Stream) {
	// copy nonce first
	if len(p.Nonce) != 0 {
		msgbuf := p.growBuf(0, AEAD_NONCE_LENGTH)
		copy(msgbuf, p.Nonce)
	}
	//dummy := make([]byte, 0)
	//for i:=0; i<32; i++ {
	//	dummy = append(dummy, 0xFF)
	//}
	// copy cornerstones
	for _, stone := range p.Header.Cornerstones {
		msgbuf := p.growBuf(stone.Offset, stone.Offset+stone.KeyPair.Hiding.HideLen())
		copy(msgbuf, stone.KeyPair.Hiding.HideEncode(stream))
		//copy(msgbuf, dummy)
	}

	// encrypt and copy entries
	payloadOffset := make([]byte, OFFSET_POINTER_LEN)
	binary.BigEndian.PutUint32(payloadOffset, uint32(p.Header.Length))
	//log.Printf("Payload starts at %d", p.Header.Length)
	entryData := append(p.key, payloadOffset...)
	for _, entries := range p.Header.EntryPoints {
		for _, entry := range entries {
			switch keywrap {
			case STREAM:
				// we use shared secret as a seed to a stream cipher
				//sec := entry.Recipient.Suite.XOF(entry.SharedSecret)
				xof := entry.Recipient.Suite.XOF(entry.SharedSecret)
				msgbuf := p.growBuf(entry.Offset, entry.Offset+p.Header.EntryPointLength)
				xof.XORKeyStream(msgbuf, entryData)
			case AEAD:

			}

			//log.Printf("EntryPoint content to place: %x", msgbuf)
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
	for _, stone := range p.Header.Cornerstones {
		stones = append(stones, stone)
	}
	sort.Slice(stones, func(i, j int) bool {
		return stones[i].Offset < stones[j].Offset
	})
	for _, stone := range stones {
		//log.Println("Write for: ", stone.SuiteName)
		keylen := stone.KeyPair.Hiding.HideLen()
		corbuf := make([]byte, keylen)
		for _, offset := range infoMap[stone.SuiteName].AllowedPositions {
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
		key := make([]byte, SYMMETRIC_KEY_LENGTH)
		random.Bytes(key, stream)
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
	low := si.AllowedPositions[level]
	high := low + si.KeyLen
	return low, high
}

func NewEntryPoint(recipient Recipient) *EntryPoint {
	return &EntryPoint{
		Recipient:    recipient,
		SharedSecret: make([]byte, SYMMETRIC_KEY_LENGTH),
		Offset:       -1,
	}
}

func NewEmptyHeader() *Header {
	return &Header{
		EntryPoints:  make(map[string][]*EntryPoint),
		Cornerstones: make(map[string]*Cornerstone),
		Length:       0,
		EntryPointLength: 0,
		Layout: nil,
	}
}

func NewPurb(key []byte, nonce []byte) (*Purb, error) {
	if len(nonce) != AEAD_NONCE_LENGTH {
		return nil, errors.New("incorrect nonce size")
	}
	if len(key) != SYMMETRIC_KEY_LENGTH {
		return nil, errors.New("incorrect symmetric key size")
	}
	return &Purb{
		Nonce: nonce,
		key:   key,
		buf:   make([]byte, 0),
	}, nil
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 1, CORNERSTONE_LENGTH, sha256.New)
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
