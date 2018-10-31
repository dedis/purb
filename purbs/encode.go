package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"sort"
	"strconv"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"fmt"
)

const SYMMETRIC_KEY_LENGTH = 16
const OFFSET_POINTER_LEN = 4
const AEAD_NONCE_LENGTH = 12
const MAC_AUTHENTICATION_TAG_LENGTH = SYMMETRIC_KEY_LENGTH
// for simplicity assuming all suites HideLen is the same).
const CORNERSTONE_LENGTH = 32

// Approaches to wrap a symmetric PayloadKey used to encrypt the payload
type SYMMETRIC_KEY_WRAPPER_TYPE int8
const (
	STREAM SYMMETRIC_KEY_WRAPPER_TYPE = iota // encrypt symmetric PayloadKey with a stream cipher
	AEAD  // encrypt symmetric PayloadKey with a AEAD
)

// Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
var HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS = 3

func PURBEncode(data []byte, recipients []Recipient, infoMap SuiteInfoMap, keywrap SYMMETRIC_KEY_WRAPPER_TYPE, stream cipher.Stream, simplifiedEntryPointTable bool, verbose bool) ([]byte, error) {

	// generate payload PayloadKey and global nonce. It could be passed by an application above
	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, AEAD_NONCE_LENGTH)
	random.Bytes(key, stream)
	random.Bytes(nonce, stream)

	// some sanity check
	if len(nonce) != AEAD_NONCE_LENGTH {
		return nil, errors.New("incorrect nonce size")
	}
	if len(key) != SYMMETRIC_KEY_LENGTH {
		return nil, errors.New("incorrect symmetric PayloadKey size")
	}

	// create the PURB datastructure
	purb := &Purb{
		Nonce:      nonce,
		Header: nil,
		Payload: nil,
		PayloadKey: key,

		isVerbose: verbose,
		recipients: recipients,
		infoMap: infoMap,
		symmKeyWrapType: keywrap,
		stream: stream,
	}

	if verbose {
		fmt.Printf("Created an empty PURB %+v\n", purb)
	}

	purb.Header = newEmptyHeader()
	switch purb.symmKeyWrapType {
	case STREAM:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	purb.createCornerStoneAndEntryPoints()
	purb.computeSharedSecrets()

	purb.Header.Layout.Reset()
	orderedSuites, err := purb.placeCornerstones()
	if err != nil {
		panic(err)
	}

	if simplifiedEntryPointTable {
		purb.placeEntrypointsSimplified(orderedSuites)
	} else {
		purb.placeEntrypoints(orderedSuites)
	}

	if err := purb.padThenEncryptData(data, stream); err != nil {
		return nil, err
	}

	return purb.ToBytes(), nil
}

// Find what unique suites used by the Recipients, generate a private for each of these suites, and assign them to corresponding entry points
func (purb *Purb) createCornerStoneAndEntryPoints() {

	recipients := purb.recipients
	header := purb.Header

	for _, recipient := range recipients {

		// create the entrypoint that will match this cornerstone
		if len(header.EntryPoints[recipient.SuiteName]) == 0 {
			header.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}
		header.EntryPoints[recipient.SuiteName] = append(header.EntryPoints[recipient.SuiteName], newEntryPoint(recipient))

		// now create the said cornerstone. We skip if we already have a cornerstone for this suite (LB->Kirill: can't two recipients share the same suite?)
		if header.Cornerstones[recipient.SuiteName] != nil {
			continue
		}

		var keyPair *key.Pair
		for {
			// Generate a fresh PayloadKey keyPair of a private PayloadKey (scalar), a public PayloadKey (point), and hidden encoding of the public PayloadKey
			keyPair = key.NewHidingKeyPair(recipient.Suite)

			if keyPair.Private == nil || keyPair.Public == nil {
				continue
			}
			if keyPair.Hiding == nil {
				continue
			}

			if keyPair.Hiding.HideLen() != purb.infoMap[recipient.SuiteName].KeyLen {
				log.Fatal("Length of elligator Encoded PayloadKey is not what we expect. It's ", keyPair.Hiding.HideLen())
			}

			// key is OK!
			break
		}

		// register a new cornerstone for this suite
		header.Cornerstones[recipient.SuiteName] = &Cornerstone{
			SuiteName: recipient.SuiteName,
			KeyPair:   keyPair,
			Offset:    -1, // we don't know this yet
		}
	}
}

// Compute a shared secret per entrypoint used to encrypt it. It takes a public PayloadKey of a recipient and multiplies it by fresh private PayloadKey for a given cipher suite.
func (purb *Purb) computeSharedSecrets() {

	// for each entrypoint in each suite
	for suiteName, entrypoints := range purb.Header.EntryPoints {
		for i, entrypoint := range entrypoints {

			cornerstone, found := purb.Header.Cornerstones[suiteName]
			if !found {
				panic("no freshly generated private PayloadKey exists for this ciphersuite")
			}

			recipientKey := entrypoint.Recipient.PublicKey
			senderKey := cornerstone.KeyPair.Private

			sharedKey := recipientKey.Mul(senderKey, recipientKey) // Compute shared DH PayloadKey
			if sharedKey == nil {
				panic("couldn't negotiate a shared DH PayloadKey")
			}

			sharedBytes, err := sharedKey.MarshalBinary()
			if err != nil {
				panic("error" + err.Error())
			}
			// Derive a PayloadKey using KDF
			purb.Header.EntryPoints[suiteName][i].SharedSecret = KDF(sharedBytes)

			//h.EntryPoints[suiteName][i].SharedSecret, _ = sharedKey.MarshalBinary()
			//fmt.Printf("Shared secret: %x and length is %d\n", h.EntryPoints[suiteName][i].SharedSecret,
			//	len(h.EntryPoints[suiteName][i].SharedSecret))
		}
	}
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (purb *Purb) placeCornerstones() ([]string, error) {
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
	purb.Header.Layout.Reserve(0, AEAD_NONCE_LENGTH, true, "nonce")

	// copy all cornerstones
	cornerstones := make([]*Cornerstone, 0)
	for _, cornerstone := range purb.Header.Cornerstones {
		cornerstones = append(cornerstones, cornerstone)
	}

	// Sort the cornerstones such as the ones with the longest PayloadKey length are placed first.
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

		suiteInfo := purb.infoMap[cornerstone.SuiteName]
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
		purb.Header.Cornerstones[cornerstone.SuiteName].Offset = suiteInfo.AllowedPositions[primary]

		// Permanently reserve the primary point position in h.Layout
		startBit, endBit := suiteInfo.region(primary)
		if endBit > purb.Header.Length {
			purb.Header.Length = endBit
		}
		//log.Printf("reserving [%d-%d] for suite %s\n", startBit, endBit, cornerstone.SuiteName)
		if !purb.Header.Layout.Reserve(startBit, endBit, true, cornerstone.SuiteName) {
			panic("thought we had that position reserved??")
		}
	}
	return orderedSuites, nil
}

// placeEntrypoints will find, place and reserve part of the header for the data
// All hash tables start after their cornerstone.
func (purb *Purb) placeEntrypoints(orderedSuites []string) {
	for _, suite := range orderedSuites {
		for entrypointID, entrypoint := range purb.Header.EntryPoints[suite] {

			//hash table initialStartPos right after the cornerstone's offset-0
			initialStartPos := purb.infoMap[suite].AllowedPositions[0] + purb.infoMap[suite].KeyLen

			//initial hash table size
			tableSize := 1
			positionFound := false
			hash := sha256.New()
			hash.Write(entrypoint.SharedSecret)
			intOfHashedValue := int(binary.BigEndian.Uint32(hash.Sum(nil))) // Large number to become a position
			var posInHashTable int

			// we start with a 1-sized hash table, try to place (and break on success), otherwise it grows by 2
			for {
				for j := 0; j < HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS; j++ {
					posInHashTable = (intOfHashedValue + j) % tableSize

					effectiveStartPos := initialStartPos + posInHashTable * purb.Header.EntryPointLength
					effectiveEndPos := initialStartPos + (posInHashTable+1) * purb.Header.EntryPointLength

					if purb.Header.Layout.Reserve(effectiveStartPos, effectiveEndPos, true, "hash"+strconv.Itoa(tableSize)) {
						purb.Header.EntryPoints[suite][entrypointID].Offset = effectiveStartPos
						positionFound = true
						//log.Printf("Placing entrypoint at [%d-%d]", initialStartPos+posInHashTable*h.EntryPointLength, initialStartPos+(posInHashTable+1)*h.EntryPointLength)
						break
					}
				}
				if positionFound {
					// save end of the current table as the length of the header
					effectiveEndPos := initialStartPos + (posInHashTable+1) * purb.Header.EntryPointLength
					if effectiveEndPos > purb.Header.Length {
						purb.Header.Length = effectiveEndPos
					}
					break
				}

				//If we haven't positionFound the entrypoint, update the hash table size and initialStartPos
				//initialStartPos = current hash table initialStartPos + number of entries in the table* the length of each entrypoint
				initialStartPos += tableSize * purb.Header.EntryPointLength
				tableSize *= 2
			}
		}
	}
}

// placeEntrypoints will find, place and reserve part of the header for the data. Does not use a hash table, put the points linearly
func (purb *Purb) placeEntrypointsSimplified(orderedSuites []string) {
	for _, suite := range orderedSuites {
		for entryPointID := range purb.Header.EntryPoints[suite] {
			//hash table startPos right after the cornerstone's offset-0
			startPos := purb.infoMap[suite].AllowedPositions[0] + purb.infoMap[suite].KeyLen

			for {
				if purb.Header.Layout.Reserve(startPos, startPos+purb.Header.EntryPointLength, true, "hash"+strconv.Itoa(startPos)) {
					purb.Header.EntryPoints[suite][entryPointID].Offset = startPos
					endPos := startPos + purb.Header.EntryPointLength
					if endPos > purb.Header.Length {
						purb.Header.Length = endPos
					}
					//log.Printf("Placing entry at [%d-%d]", startPos, startPos+h.EntryPointLength)
					break
				} else {
					startPos += purb.Header.EntryPointLength
				}
			}
		}
	}
}

// padThenEncryptData takes plaintext data as a byte slice, pads it using PURBs padding scheme,
// and then encrypts using AEAD encryption scheme
func (p *Purb) padThenEncryptData(data []byte, stream cipher.Stream) error {
	var err error
	paddedData := Pad(data, p.Header.Length+MAC_AUTHENTICATION_TAG_LENGTH)
	p.Payload, err = aeadEncrypt(paddedData, p.Nonce, p.PayloadKey, nil, stream)
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Print(paddedData)
	return nil
}

// Encrypt the payload of the purb using freshly generated symmetric keys and AEAD.
func aeadEncrypt(data, nonce, key, additional []byte, stream cipher.Stream) ([]byte, error) {

	// Generate a random 16-byte PayloadKey and create a cipher from it
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
	encrypted := aesgcm.Seal(nil, nonce, data, additional) // additional can be nil

	return encrypted, nil
}

func newEntryPoint(recipient Recipient) *EntryPoint {
	return &EntryPoint{
		Recipient:    recipient,
		SharedSecret: make([]byte, SYMMETRIC_KEY_LENGTH),
		Offset:       -1,
	}
}

func newEmptyHeader() *Header {
	return &Header{
		EntryPoints:  make(map[string][]*EntryPoint),
		Cornerstones: make(map[string]*Cornerstone),
		Length:       0,
		EntryPointLength: 0,
	}
}

// Return the byte-range for a point at a given level.
func (si *SuiteInfo) region(level int) (int, int) {
	low := si.AllowedPositions[level]
	high := low + si.KeyLen
	return low, high
}