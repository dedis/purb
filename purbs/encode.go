package purbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"sort"
	"strconv"
)

// Creates a struct with parameters that are *fixed* across all PURBs. Should be constants, but here it is a variable for simulating various parameters
func NewPublicFixedParameters(infoMap SuiteInfoMap, simplifiedEntryPointTable bool) *PurbPublicFixedParameters {
	return &PurbPublicFixedParameters{
		SuiteInfoMap:                               infoMap,
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

	// creation of the global Nonce and random playload key
	purb.Nonce = purb.randomBytes(AEAD_NONCE_LENGTH)
	purb.PayloadKey = purb.randomBytes(SYMMETRIC_KEY_LENGTH)

	if purb.IsVerbose {
		log.LLvlf3("Created an empty PURB, original data %v, payload key %v, nonce %v", data, purb.PayloadKey, purb.Nonce)
		log.LLvlf3("Recipients %+v", recipients)
		for i := range purb.PublicParameters.SuiteInfoMap {
			log.LLvlf3("SuiteInfoMap [%v]: len %v, positions %+v", i, purb.PublicParameters.SuiteInfoMap[i].CornerstoneLength, purb.PublicParameters.SuiteInfoMap[i].AllowedPositions)
		}
	}

	// creation of the entrypoints and cornerstones, places entrypoint and cornerstones
	purb.CreateHeader()

	// creation of the encrypted payload
	purb.padThenEncryptData(data, stream)

	// converts everything to []byte, performs the XOR trick on the cornerstones
	purb.placePayloadAndCornerstones()

	return purb, nil
}

// Construct header computes and finds an appropriate placements for the Entrypoints and the Cornerstones
func (purb *Purb) CreateHeader() {

	purb.Header = newEmptyHeader()

	purb.createCornerstones()
	purb.createEntryPoints()
	purb.placeCornerstones()

	if purb.PublicParameters.SimplifiedEntrypointsPlacement {
		purb.placeEntrypointsSimplified()
	} else {
		purb.placeEntrypoints()
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

			if keyPair.Hiding.HideLen() > purb.PublicParameters.SuiteInfoMap[recipient.SuiteName].CornerstoneLength {
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
			Length:       purb.PublicParameters.SuiteInfoMap[recipient.SuiteName].EntryPointLength,
		}

		// store entrypoint
		if len(header.EntryPoints[recipient.SuiteName]) == 0 {
			header.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}

		header.EntryPoints[recipient.SuiteName] = append(header.EntryPoints[recipient.SuiteName], ep)
	}
}

func placeCornerstonesHelper(
	mainLayout *RegionReservationStruct,
	secondaryLayout *RegionReservationStruct,
	cornerstonesToPlace []*Cornerstone,
	placedCornerstones []*Cornerstone,
	verbose bool) []*Cornerstone {

	if len(cornerstonesToPlace) == 0 {
		if verbose {
			log.LLvlf3("Placed all cornerstones!")
			for _, c := range placedCornerstones {
				log.LLvl3("  ", c.SuiteName, "between", c.Offset, c.EndPos)
			}
		}
		return placedCornerstones
	}

	// iteratively try to place remaining cornerstone
	for _, cornerstone := range cornerstonesToPlace {

		// prepare datastructure for recursion, do deep copies
		placedCornerstones2 := make([]*Cornerstone, 0)
		for _, c := range placedCornerstones {
			placedCornerstones2 = append(placedCornerstones2, &Cornerstone{
				SuiteName: c.SuiteName,
				SuiteInfo: c.SuiteInfo,
				EndPos:    c.EndPos,
				Offset:    c.Offset,
			})
		}
		mainLayout2 := mainLayout.Clone()
		secondaryLayout2 := secondaryLayout.Clone()

		// try to place this one
		suiteInfo := cornerstone.SuiteInfo
		allowedPositions := cornerstone.SuiteInfo.AllowedPositions

		// find the first free position in the layout. We use the "secondaryLayout" since secondary positions are *not* free for other cornerstones !
		smallestNonConflictingIndex := -1

		for index, startPos := range allowedPositions {
			endPos := startPos + suiteInfo.CornerstoneLength

			if secondaryLayout2.IsFree(startPos, endPos) {
				smallestNonConflictingIndex = index
				break
			}
		}

		// no a valid placement, return
		if smallestNonConflictingIndex == -1 {
			return nil
		}

		// We found the position for this suite, reserve it ...
		startBit, endBit := suiteInfo.byteRangeForAllowedPositionIndex(smallestNonConflictingIndex)
		if !mainLayout2.Reserve(startBit, endBit, true, cornerstone.SuiteName) {
			panic("The position is supposed to be free !")
		}
		for _, startPos := range allowedPositions {
			endPos := startPos + suiteInfo.CornerstoneLength

			// we don't care if we get those bytes exclusively (hence requireFree=false), we just want to prevent
			// future suites/cornerstone from using them as a primary position
			secondaryLayout2.Reserve(startPos, endPos, false, cornerstone.SuiteName)
		}
		placedCornerstones2 = append(placedCornerstones2, &Cornerstone{
			SuiteName: cornerstone.SuiteName,
			Offset:    startBit,
			EndPos:    endBit,
		})

		if verbose {
			log.LLvl3("Attempting position", startBit, endBit, "for suite", cornerstone.SuiteName)
		}

		// filter the one we just placed
		remainingCornerstones := make([]*Cornerstone, 0)
		for _, c := range cornerstonesToPlace {
			if c.SuiteName != cornerstone.SuiteName {
				remainingCornerstones = append(remainingCornerstones, &Cornerstone{
					SuiteName: c.SuiteName,
					SuiteInfo: c.SuiteInfo,
					EndPos:    c.EndPos,
					Offset:    c.Offset,
				})
			}
		}

		// proceed recursively
		res := placeCornerstonesHelper(mainLayout2, secondaryLayout2, remainingCornerstones, placedCornerstones2, verbose)
		if res != nil {
			// we found a solution, stop iterating
			return res
		}
	}

	return nil
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (purb *Purb) placeCornerstones() {

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

	cornerstonesToPlace := make([]*Cornerstone, 0)
	cornerstonesPlaced := make([]*Cornerstone, 0)
	for _, cornerstone := range purb.Header.Cornerstones {
		cornerstonesToPlace = append(cornerstonesToPlace, cornerstone)
	}

	placedCornerstones := placeCornerstonesHelper(mainLayout, secondaryLayout, cornerstonesToPlace, cornerstonesPlaced, purb.IsVerbose)

	if placedCornerstones == nil {
		panic("Could not find a mapping for placing the cornerstone, who designed the AllowedPositions ?!")
	}

	// for each cornerstone, register its position
	for _, cornerstone := range placedCornerstones {

		// ... in the cornerstone struct (which will be used when placing the entrypoints)
		purb.Header.Cornerstones[cornerstone.SuiteName].Offset = cornerstone.Offset
		purb.Header.Cornerstones[cornerstone.SuiteName].EndPos = cornerstone.EndPos

		if !mainLayout.Reserve(cornerstone.Offset, cornerstone.EndPos, true, cornerstone.SuiteName) {
			panic("I thought we had this position reserved")
		}

		if purb.IsVerbose {
			log.LLvlf3("Position for cornerstone %v is start %v, end %v", cornerstone.SuiteName, cornerstone.Offset, cornerstone.EndPos)
		}
	}
}

// placeEntrypoints will find, place and reserve part of the header for the data
// All hash tables start after their cornerstone.
func (purb *Purb) placeEntrypoints() {
	for _, cornerstone := range purb.Header.Cornerstones {
		suite := cornerstone.SuiteName
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
			for !positionFound {

				// before doubling, consider HashTableCollisionLinearResolutionAttempts
				for j := 0; j < purb.PublicParameters.HashTableCollisionLinearResolutionAttempts; j++ {
					posInHashTable = (intOfHashedValue + j) % tableSize

					effectiveStartPos := initialStartPos + posInHashTable*entrypoint.Length
					effectiveEndPos := initialStartPos + (posInHashTable+1)*entrypoint.Length

					if purb.Header.Layout.Reserve(effectiveStartPos, effectiveEndPos, true, "hash"+strconv.Itoa(tableSize)) {
						purb.Header.EntryPoints[suite][entrypointID].Offset = effectiveStartPos
						positionFound = true

						if purb.IsVerbose {
							log.LLvlf3("Found position for entrypoint %v of suite %v, table size %v, linear %v, start %v, end %v", entrypointID, suite, tableSize, j, effectiveStartPos, effectiveEndPos)
						}

						break
					}
				}

				if !positionFound {
					//If we haven't positionFound the entrypoint, update the hash table size and initialStartPos
					//initialStartPos = current hash table initialStartPos + number of entries in the table* the length of each entrypoint
					initialStartPos += tableSize * entrypoint.Length
					tableSize *= 2
				}
			}
		}
	}
}

// placeEntrypoints will findAllRangesStrictlyBefore, place and reserve part of the header for the data. Does not use a hash table, put the points linearly
func (purb *Purb) placeEntrypointsSimplified() {

	for _, cornerstone := range purb.Header.Cornerstones {
		suite := cornerstone.SuiteName
		for entryPointID, entrypoint := range purb.Header.EntryPoints[suite] {
			//hash table startPos right after the cornerstone's offset-0
			startPos := purb.PublicParameters.SuiteInfoMap[suite].AllowedPositions[0] + purb.PublicParameters.SuiteInfoMap[suite].CornerstoneLength

			for {
				if purb.Header.Layout.Reserve(startPos, startPos+entrypoint.Length, true, "hash"+strconv.Itoa(startPos)) {
					purb.Header.EntryPoints[suite][entryPointID].Offset = startPos
					endPos := startPos + entrypoint.Length

					if purb.IsVerbose {
						log.LLvlf3("Found position for entrypoint %v of suite %v, SIMPLIFIED, start %v, end %v", entryPointID, suite, startPos, endPos)
					}

					//log.Printf("Placing entry at [%d-%d]", startPos, startPos+h.EntryPointLength)
					break
				} else {
					startPos += entrypoint.Length
				}
			}
		}
	}
}

// padThenEncryptData takes plaintext data as a byte slice, pads it using PURBs padding scheme,
// and then encrypts using AEAD encryption scheme
func (purb *Purb) padThenEncryptData(data []byte, stream cipher.Stream) {
	paddedData := pad(data, purb.Header.Length()+MAC_AUTHENTICATION_TAG_LENGTH)

	if purb.IsVerbose {
		log.LLvlf3("Payload padded from %v to %v bytes", len(data), len(paddedData))
	}

	payload, err := aeadEncrypt(paddedData, purb.Nonce, purb.PayloadKey, nil, stream)
	if err != nil {
		log.Fatal(err.Error())
	}
	purb.Payload = payload

	if purb.IsVerbose {
		log.LLvlf3("Payload padded encrypted to %v (len %v)", purb.Payload, len(purb.Payload))
	}
}

// ToBytes writes content of entrypoints and encrypted payloads into contiguous buffer
func (purb *Purb) placePayloadAndCornerstones() {
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

			// we use shared secret as a seed to a Stream cipher
			xof := entrypoint.Recipient.Suite.XOF(entrypoint.SharedSecret)
			startPos := entrypoint.Offset
			endPos := startPos + entrypoint.Length

			region := buffer.growAndGetRegion(startPos, endPos)
			xof.XORKeyStream(region, entrypointContent)

			if purb.IsVerbose {
				log.LLvlf3("Adding symmetric entrypoint in [%v:%v], plaintext value %v, encrypted value %v with key %v, len %v", startPos, endPos, entrypointContent, region, entrypoint.SharedSecret, len(entrypointContent))
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
				if b < len(region) {
					thisByte := region[b]
					xorOfAllPositions[b] ^= thisByte
				}
			}
		}

		// copy the result of XOR to the primary position
		startPos := cornerstone.Offset
		endPos := startPos + cornerstoneLength
		buffer.copyInto(startPos, endPos, xorOfAllPositions)
	}

	purb.byteRepresentation = buffer.toBytes()
}

// Encrypt using AEAD
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
	encrypted := aesgcm.Seal(nil, nonce, data, additional)

	return encrypted, nil
}

// ToBytes get the []byte representation of the PURB
func (purb *Purb) ToBytes() []byte {
	return purb.byteRepresentation
}

func (purb *Purb) randomBytes(length int) []byte {
	buffer := make([]byte, length)
	random.Bytes(buffer, purb.Stream)
	return buffer
}

func newEmptyHeader() *Header {
	return &Header{
		EntryPoints:  make(map[string][]*EntryPoint),
		Cornerstones: make(map[string]*Cornerstone),
		Layout:       NewRegionReservationStruct(),
	}
}

func (purb *Purb) newCornerStone(suiteName string, keyPair *key.Pair) *Cornerstone {

	hiddenBytes := keyPair.Hiding.HideEncode(purb.Stream)
	hiddenBytes2 := make([]byte, purb.PublicParameters.SuiteInfoMap[suiteName].CornerstoneLength)

	// copy at the end
	copy(hiddenBytes2[len(hiddenBytes2)-len(hiddenBytes):], hiddenBytes[:])
	return &Cornerstone{
		SuiteName: suiteName,
		Offset:    -1,
		KeyPair:   keyPair, // do not call Hiding.HideEncode on this! it has been done already. Use bytes
		Bytes:     hiddenBytes2,
		SuiteInfo: purb.PublicParameters.SuiteInfoMap[suiteName],
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
			if length < entrypoint.Offset+entrypoint.Length {
				length = entrypoint.Offset + entrypoint.Length
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
