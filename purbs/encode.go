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
func NewPublicFixedParameters(infoMap SuiteInfoMap, keywrap ENTRYPOINT_ENCRYPTION_TYPE, simplifiedEntryPointTable bool) *PurbPublicFixedParameters {
	return &PurbPublicFixedParameters{
		SuiteInfoMap:                               infoMap,
		EntrypointEncryptionType:                   keywrap,
		SimplifiedEntrypointsPlacement:             simplifiedEntryPointTable,
		HashTableCollisionLinearResolutionAttempts: 3,
	}
}

// Creates a PURB from some data and Recipients information
func Encode(data []byte, recipients []Recipient, stream cipher.Stream, params *PurbPublicFixedParameters, verbose bool) (*Purb, error) {

	// create the PURB datastructure
	purb := &Purb{
		Nonce:            nil,
		Header:           nil,
		Payload:          nil,
		PayloadKey:       nil,
		Recipients:       recipients,
		Stream:           stream,
		OriginalData:     data, // just for statistics
		PublicParameters: params,
		IsVerbose:        verbose,
	}

	purb.Nonce = purb.randomBytes(AEAD_NONCE_LENGTH)
	purb.PayloadKey = purb.randomBytes(SYMMETRIC_KEY_LENGTH)

	if purb.IsVerbose {
		log.LLvlf3("Created an empty PURB, original data %v, payload key %v, nonce %v", data, purb.PayloadKey, purb.Nonce)
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

	purb.createCornerstones()
	purb.createEntryPoints()

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
func (purb *Purb) createCornerstones() {

	recipients := purb.Recipients
	header := purb.Header

	for _, recipient := range recipients {

		// now create the said cornerstone. We advance if we already have a cornerstone for this suite (LB->Kirill: can't two Recipients share the same suite?)
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
func (purb *Purb) createEntryPoints() {

	recipients := purb.Recipients
	header := purb.Header

	// create an empty entrypoint per suite, indexed per suite
	for _, recipient := range recipients {

		// fetch the cornerstone containing the freshly-generated public key for this suite
		cornerstone, found := header.Cornerstones[recipient.SuiteName]
		if !found {
			panic("no freshly generated private PayloadKey exists for this ciphersuite")
		}

		// compute shared key for the entrypoint
		recipientKey := recipient.PublicKey
		senderKey := cornerstone.KeyPair.Private
		sharedKey := recipientKey.Mul(senderKey, recipientKey)

		if sharedKey == nil {
			panic("couldn't negotiate a shared DH PayloadKey")
		}

		sharedBytes, err := sharedKey.MarshalBinary()
		if err != nil {
			panic("error" + err.Error())
		}

		// derive a PayloadKey using KDF
		sharedSecret := KDF(sharedBytes)

		if purb.IsVerbose {
			log.LLvlf3("Shared secret with suite=%v, entrypoint value %v", recipient.SuiteName, sharedBytes)
		}

		ep := &EntryPoint{
			Recipient:    recipient,
			SharedSecret: sharedSecret,
			Offset:       -1,
		}

		// store entrypoint
		if len(header.EntryPoints[recipient.SuiteName]) == 0 {
			header.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}

		header.EntryPoints[recipient.SuiteName] = append(header.EntryPoints[recipient.SuiteName], ep)
	}
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (purb *Purb) placeCornerstones() ([]string, error) {

	// To compute the "main layout", we use a secondary layout to keep track of things. It is discarded at the end, and only helps computing mainLayout.
	// Two things to remember:
	// (1) every Suite has *multiple possible positions* for placing a cornerstone.
	// (2) when the PURB is finalized, the decoder can XOR *all possible positions* (within the payload) to get the cornerstone
	// In principle, when we found the primary position for a suite, we don't care what's gonna be in the remaining positions,
	// *but* it cannot be another cornerstone since we need to ensure there is at least one degree of freedom to ensure property
	// (2). Hence, we place cornerstone where they don't collide with other "things" in the primary payload (which is normal),
	// but also they cannot collide with other suite's allowed positions (represented by the secondaryLayout).
	// On the other hand, other "things" (entrypoints, data), can collide with the non-primary positions of the suites.
	// Final note: we start by placing the "longest" (bit-wise) cornerstone since it has more chance to collide with something
	// when placed.
	mainLayout := purb.Header.Layout
	secondaryLayout := NewRegionReservationStruct()

	// we first reserve the spot for the nonce
	mainLayout.Reserve(0, AEAD_NONCE_LENGTH, true, "nonce")
	secondaryLayout.Reserve(0, AEAD_NONCE_LENGTH, true, "nonce")

	// we then sort the sortedCornerstones by their length
	sortedCornerstones := make([]*Cornerstone, 0)
	for _, cornerstone := range purb.Header.Cornerstones {
		sortedCornerstones = append(sortedCornerstones, cornerstone)
	}

	sortFunction := func(i, j int) bool {
		if len(sortedCornerstones[i].Bytes) > len(sortedCornerstones[j].Bytes) {
			return true
		}
		if len(sortedCornerstones[i].Bytes) == len(sortedCornerstones[j].Bytes) {
			return sortedCornerstones[i].SuiteName < sortedCornerstones[j].SuiteName
		}
		return false
	}

	sort.Slice(sortedCornerstones, sortFunction)

	// we find the suite informations (in the same order as the cornerstones)
	sortedSuites := make([]string, 0)
	for _, cornerstone := range sortedCornerstones {
		suiteInfo := purb.PublicParameters.SuiteInfoMap[cornerstone.SuiteName]
		if suiteInfo == nil {
			return nil, errors.New("we do not have suiteInfo about the needed suite")
		}
		sortedSuites = append(sortedSuites, cornerstone.SuiteName)
	}

	// for each cornerstone,
	for index, cornerstone := range sortedCornerstones {

		suiteInfo := purb.PublicParameters.SuiteInfoMap[sortedSuites[index]]
		allowedPositions := suiteInfo.AllowedPositions

		// find the first free position in the layout. We use the "secondaryLayout" since secondary positions are *not* free for other cornerstones !
		smallestNonConflictingIndex := -1
		for index, startPos := range allowedPositions {
			endPos := startPos + suiteInfo.CornerstoneLength

			if secondaryLayout.IsFree(startPos, endPos) {
				smallestNonConflictingIndex = index
				break
			}
		}

		if smallestNonConflictingIndex == -1 {
			return nil, errors.New("no viable position for suite " + cornerstone.SuiteName)
		}

		// We found the position for this suite, reserve it ...
		startBit, endBit := suiteInfo.byteRangeForAllowedPositionIndex(smallestNonConflictingIndex)

		// ... in the main layout
		if !mainLayout.Reserve(startBit, endBit, true, cornerstone.SuiteName) {
			panic("The position is supposed to be free !")
		}

		// ... in the cornerstone struct (which will be used when placing the entrypoints)
		purb.Header.Cornerstones[cornerstone.SuiteName].Offset = startBit
		purb.Header.Cornerstones[cornerstone.SuiteName].EndPos = endBit


		if purb.IsVerbose {
			log.LLvlf3("Found position for cornerstone %v, start %v, end %v", cornerstone.SuiteName, startBit, endBit)
		}

		// finally, reserve *all* possible position in the secondaryLayout. The final step of the PURB
		// creation is to ensure that the XOR of those values equals the value of the cornerstone, so we must have some
		// degree of freedom here, we can't place other cornerstones

		for _, startPos := range allowedPositions {
			endPos := startPos + suiteInfo.CornerstoneLength

			// we don't care if we get those bytes exclusively (hence requireFree=false), we just want to prevent
			// future suites/cornerstone from using them as a primary position
			secondaryLayout.Reserve(startPos, endPos, false, cornerstone.SuiteName)
		}
	}

	return sortedSuites, nil
}

// placeEntrypoints will findAllRangesStrictlyBefore, place and reserve part of the header for the data
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
				for j := 0; j < purb.PublicParameters.HashTableCollisionLinearResolutionAttempts; j++ {
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

// placeEntrypoints will findAllRangesStrictlyBefore, place and reserve part of the header for the data. Does not use a hash table, put the points linearly
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
	paddedData := pad(data, purb.Header.Length() + MAC_AUTHENTICATION_TAG_LENGTH)

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
	binary.BigEndian.PutUint32(payloadOffset, uint32(purb.Header.Length()))

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
	purb.Header.Layout.ScanFreeRegions(fillRndFunction, buffer.length())

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
					// the position is fully outside the blob; we advanceIteratorUntil this cornerstone
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

func (purb *Purb) randomBytes(length int) []byte {
	buffer := make([]byte, length)
	random.Bytes(buffer, purb.Stream)
	return buffer
}

func newEmptyHeader() *Header {
	return &Header{
		EntryPoints:      make(map[string][]*EntryPoint),
		Cornerstones:     make(map[string]*Cornerstone),
		EntryPointLength: 0,
		Layout:           NewRegionReservationStruct(),
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

// Return the byte-range (start:end) for a cornerstone's position index.
func (si *SuiteInfo) byteRangeForAllowedPositionIndex(index int) (int, int) {
	low := si.AllowedPositions[index]
	high := low + si.CornerstoneLength
	return low, high
}

// Compute the length of the header when transformed to []byte
func (h *Header) Length() int {
	length := AEAD_NONCE_LENGTH

	for _, entryPoints := range h.EntryPoints {
		for _, entrypoint := range entryPoints {
			if length < entrypoint.Offset + h.EntryPointLength {
				length = entrypoint.Offset + h.EntryPointLength
			}
		}
	}

	for _, cornerstone := range h.Cornerstones {
		if length < cornerstone.EndPos {
			length = cornerstone.EndPos
		}
	}

	return length
}
