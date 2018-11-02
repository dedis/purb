package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"sort"
	"strconv"
)

// Creates a struct with parameters that are *fixed* across all PURBs. Should be constants, but here it is a variable for simulating various parameters
func NewPublicFixedParameters(infoMap SuiteInfoMap, keywrap SYMMETRIC_KEY_WRAPPER_TYPE, simplifiedEntryPointTable bool) *PurbPublicFixedParameters {
	return &PurbPublicFixedParameters{
		SuiteInfoMap:                   infoMap,
		EntrypointEncryptionType:       keywrap,
		SimplifiedEntrypointsPlacement: simplifiedEntryPointTable,
	}
}

// Creates a PURB from some data and Recipients information
func Encode(data []byte, recipients []Recipient, stream cipher.Stream, params *PurbPublicFixedParameters, verbose bool) (*Purb, error) {

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
		Nonce:            nonce,
		Header:           nil,
		Payload:          nil,
		PayloadKey:       key,
		Recipients:       recipients,
		Stream:           stream,
		OriginalData:     data, // just for statistics
		PublicParameters: params,
		IsVerbose:        verbose,
	}

	if purb.IsVerbose {
		log.LLvlf3("Created an empty PURB, original data %v, payload key %v, nonce %v", data, key, nonce)
		log.LLvlf3("Recipients %+v", recipients)
		for i := range purb.PublicParameters.SuiteInfoMap {
			log.LLvlf3("SuiteInfoMap [%v]: len %v, positions %+v", i, purb.PublicParameters.SuiteInfoMap[i].CornerstoneLength, purb.PublicParameters.SuiteInfoMap[i].AllowedPositions)
		}
	}

	purb.ConstructHeader()

	if err := purb.padThenEncryptData(data, stream); err != nil {
		return nil, err
	}

	// Here, things are placed where they should; only the final XORing step for entrypoint needs to be done (in "ToBytes")

	return purb, nil
}

// Construct header finds an appropriate placements for the Entrypoints and the Cornerstones
func (purb *Purb) ConstructHeader() {

	purb.Header = newEmptyHeader()
	switch purb.PublicParameters.EntrypointEncryptionType {
	case STREAM:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	purb.createCornerstonesAndEntrypoints()
	purb.computeSharedSecrets()

	purb.Header.Layout.Reset()
	orderedSuites, err := purb.placeCornerstones()
	if err != nil {
		panic(err)
	}

	if purb.PublicParameters.SimplifiedEntrypointsPlacement {
		purb.placeEntrypointsSimplified(orderedSuites)
	} else {
		purb.placeEntrypoints(orderedSuites)
	}
}

// Find what unique suites used by the Recipients, generate a private for each of these suites, and assign them to corresponding entry points
func (purb *Purb) createCornerstonesAndEntrypoints() {

	recipients := purb.Recipients
	header := purb.Header

	for _, recipient := range recipients {

		// create the entrypoint that will match this cornerstone
		if len(header.EntryPoints[recipient.SuiteName]) == 0 {
			header.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}
		header.EntryPoints[recipient.SuiteName] = append(header.EntryPoints[recipient.SuiteName], newEntryPoint(recipient))

		// now create the said cornerstone. We skip if we already have a cornerstone for this suite (LB->Kirill: can't two Recipients share the same suite?)
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

			if keyPair.Hiding.HideLen() != purb.PublicParameters.SuiteInfoMap[recipient.SuiteName].CornerstoneLength {
				log.Fatal("Length of elligator Encoded PayloadKey is not what we expect. It's ", keyPair.Hiding.HideLen())
			}

			// key is OK!
			break
		}

		// register a new cornerstone for this suite
		cornerstone := purb.newCornerStone(recipient.SuiteName, keyPair)
		header.Cornerstones[recipient.SuiteName] = cornerstone

		if purb.IsVerbose {
			log.LLvlf3("Created cornerstone[%v], value %v", recipient.SuiteName, cornerstone.Bytes)
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

			if purb.IsVerbose {
				log.LLvlf3("Shared secret with suite=%v, entrypoint[%v], value %v", suiteName, i, sharedBytes)
			}

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
		if len(cornerstones[i].Bytes) > len(cornerstones[j].Bytes) {
			return true
		}
		if len(cornerstones[i].Bytes) == len(cornerstones[j].Bytes) {
			return cornerstones[i].SuiteName < cornerstones[j].SuiteName
		}
		return false
	})

	orderedSuites := make([]string, 0)
	for _, cornerstone := range cornerstones {

		suiteInfo := purb.PublicParameters.SuiteInfoMap[cornerstone.SuiteName]
		if suiteInfo == nil {
			return nil, errors.New("we do not have suiteInfo about the needed suite")
		}

		orderedSuites = append(orderedSuites, cornerstone.SuiteName)

		// Reserve all our possible positions in excludeLayout layout,
		// picking the first non-conflicting position as our primary.
		primary := len(suiteInfo.AllowedPositions)
		for j := primary - 1; j >= 0; j-- {

			startPos := suiteInfo.AllowedPositions[j]
			endPos := startPos + suiteInfo.CornerstoneLength
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

		if purb.IsVerbose {
			log.LLvlf3("Found position for cornerstone %v, start %v, end %v", cornerstone.SuiteName, startBit, endBit)
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
			initialStartPos := purb.PublicParameters.SuiteInfoMap[suite].AllowedPositions[0] + purb.PublicParameters.SuiteInfoMap[suite].CornerstoneLength

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

					effectiveStartPos := initialStartPos + posInHashTable*purb.Header.EntryPointLength
					effectiveEndPos := initialStartPos + (posInHashTable+1)*purb.Header.EntryPointLength

					if purb.Header.Layout.Reserve(effectiveStartPos, effectiveEndPos, true, "hash"+strconv.Itoa(tableSize)) {
						purb.Header.EntryPoints[suite][entrypointID].Offset = effectiveStartPos
						positionFound = true

						if purb.IsVerbose {
							log.LLvlf3("Found position for entrypoint %v of suite %v, table size %v, linear %v, start %v, end %v", entrypointID, suite, tableSize, j, effectiveStartPos, effectiveEndPos)
						}

						break
					}
				}
				if positionFound {
					// save end of the current table as the length of the header
					effectiveEndPos := initialStartPos + (posInHashTable+1)*purb.Header.EntryPointLength
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
			startPos := purb.PublicParameters.SuiteInfoMap[suite].AllowedPositions[0] + purb.PublicParameters.SuiteInfoMap[suite].CornerstoneLength

			for {
				if purb.Header.Layout.Reserve(startPos, startPos+purb.Header.EntryPointLength, true, "hash"+strconv.Itoa(startPos)) {
					purb.Header.EntryPoints[suite][entryPointID].Offset = startPos
					endPos := startPos + purb.Header.EntryPointLength

					if purb.IsVerbose {
						log.LLvlf3("Found position for entrypoint %v of suite %v, SIMPLIFIED, start %v, end %v", entryPointID, suite, startPos, endPos)
					}

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
func (purb *Purb) padThenEncryptData(data []byte, stream cipher.Stream) error {
	var err error
	paddedData := pad(data, purb.Header.Length+MAC_AUTHENTICATION_TAG_LENGTH)

	if purb.IsVerbose {
		log.LLvlf3("Payload padded from %v to %v bytes", len(data), len(paddedData))
	}

	purb.Payload, err = aeadEncrypt(paddedData, purb.Nonce, purb.PayloadKey, nil, stream)
	if err != nil {
		log.Fatal(err.Error())
	}

	if purb.IsVerbose {
		log.LLvlf3("Payload padded encrypted to %v (len %v)", purb.Payload, len(purb.Payload))
	}

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

// ToBytes writes content of entrypoints and encrypted payloads into contiguous buffer
func (purb *Purb) ToBytes() []byte {

	buffer := new(GrowableBuffer)

	// copy nonce
	if len(purb.Nonce) != 0 {
		region := buffer.growAndGetRegion(0, AEAD_NONCE_LENGTH)
		copy(region, purb.Nonce)

		if purb.IsVerbose {
			log.LLvlf3("Adding nonce in [%v:%v], value %v, len %v", 0, AEAD_NONCE_LENGTH, purb.Nonce, len(purb.Nonce))
		}
	}

	// copy cornerstones
	for _, cornerstone := range purb.Header.Cornerstones {
		startPos := cornerstone.Offset
		length := len(cornerstone.Bytes)
		endPos := cornerstone.Offset + length

		region := buffer.growAndGetRegion(startPos, endPos)
		copy(region, cornerstone.Bytes)

		if purb.IsVerbose {
			log.LLvlf3("Adding cornerstone in [%v:%v], value %v, len %v", startPos, endPos, cornerstone.Bytes, length)
		}
	}

	// encrypt and copy entrypoints
	payloadOffset := make([]byte, OFFSET_POINTER_LEN)
	binary.BigEndian.PutUint32(payloadOffset, uint32(purb.Header.Length))

	entrypointContent := append(purb.PayloadKey, payloadOffset...)
	for _, entrypointsPerSuite := range purb.Header.EntryPoints {
		for _, entrypoint := range entrypointsPerSuite {
			switch purb.PublicParameters.EntrypointEncryptionType {
			case STREAM:
				// we use shared secret as a seed to a Stream cipher
				xof := entrypoint.Recipient.Suite.XOF(entrypoint.SharedSecret)
				startPos := entrypoint.Offset
				endPos := startPos + purb.Header.EntryPointLength

				region := buffer.growAndGetRegion(startPos, endPos)
				xof.XORKeyStream(region, entrypointContent)

				if purb.IsVerbose {
					log.LLvlf3("Adding entrypoint in [%v:%v], plaintext value %v, encrypted value %v with key %v, len %v", startPos, endPos, entrypointContent, region, entrypoint.SharedSecret, len(entrypointContent))
				}
			case AEAD:
				panic("not implemented")
			}
		}
	}

	// Fill all unused parts of the header with random bits.
	fillRndFunction := func(low, high int) {
		region := buffer.growAndGetRegion(low, high)
		purb.Stream.XORKeyStream(region, region)

		if purb.IsVerbose {
			log.LLvlf3("Adding random bytes in [%v:%v]", low, high)
		}
	}
	purb.Header.Layout.scanFree(fillRndFunction, buffer.length())

	//log.Printf("Final length of header: %d", len(p.buf))
	//log.Printf("Random with header: %x", p.buf)

	// copy message into buffer

	if purb.IsVerbose {
		log.LLvlf3("Adding payload in [%v:%v], value %v, len %v", buffer.length(), buffer.length()+len(purb.Payload), purb.Payload, len(purb.Payload))
	}
	buffer.append(purb.Payload)

	// sort cornerstone by order of apparition in the header
	cornerstones := make([]*Cornerstone, 0)
	for _, stone := range purb.Header.Cornerstones {
		cornerstones = append(cornerstones, stone)
	}
	sort.Slice(cornerstones, func(i, j int) bool {
		return cornerstones[i].Offset < cornerstones[j].Offset
	})

	// XOR each cornerstone with the data in its non-selected positions, and save as the cornerstone value
	// (hence, the XOR of all positions = the cornerstone)
	for _, cornerstone := range cornerstones {

		cornerstoneLength := len(cornerstone.Bytes)
		xorOfAllPositions := make([]byte, cornerstoneLength)

		for _, cornerstoneAllowedPos := range purb.PublicParameters.SuiteInfoMap[cornerstone.SuiteName].AllowedPositions {
			endPos := cornerstoneAllowedPos + cornerstoneLength

			// check that we have data at non-primary positions to xor
			if endPos > buffer.length() {
				if cornerstoneAllowedPos > buffer.length() {
					// the position is fully outside the blob; we skip this cornerstone
					break
				} else {
					// the position is partially inside the blob; take only this
					endPos = buffer.length()
				}
			}
			region := buffer.slice(cornerstoneAllowedPos, endPos)

			for b := 0; b < cornerstoneLength; b++ {
				xorOfAllPositions[b] ^= region[b]
			}
		}

		// copy the result of XOR to the primary position
		startPos := cornerstone.Offset
		endPos := startPos + cornerstoneLength
		buffer.copyInto(startPos, endPos, xorOfAllPositions)
	}
	return buffer.toBytes()
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
		EntryPoints:      make(map[string][]*EntryPoint),
		Cornerstones:     make(map[string]*Cornerstone),
		Length:           0,
		EntryPointLength: 0,
	}
}

func (purb *Purb) newCornerStone(suiteName string, keyPair *key.Pair) *Cornerstone {
	return &Cornerstone{
		SuiteName: suiteName,
		Offset:    -1,
		KeyPair:   keyPair, // do not call Hiding.HideEncode on this! it has been done already. Use bytes
		Bytes:     keyPair.Hiding.HideEncode(purb.Stream),
	}
}

// Return the byte-range for a point at a given level.
func (si *SuiteInfo) region(level int) (int, int) {
	low := si.AllowedPositions[level]
	high := low + si.CornerstoneLength
	return low, high
}
