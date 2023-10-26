package purb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"purb"
	"sort"
	"strconv"

	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
)

// Creates a PURB from some data and Recipients information
func (p *Purb) Encode(
	data []byte,
) error {
	p.originalData = data

	// creation of the global Nonce and random playload key
	p.nonce = p.randomBytes(NonceLength)
	p.sessionKey = p.randomBytes(SymmetricKeyLength)

	purb.Logger.Info().Msgf("Created an empty PURB, original data %v, payload key %v, nonce %v",
		data, p.sessionKey, p.nonce)
	purb.Logger.Debug().Msgf("Recipients %+v", p.Recipients)
	for i := range p.config.suiteInfoMap {
		purb.Logger.Debug().Msgf("SuiteInfoMap [%v]: len %v, positions %+v", i,
			p.config.suiteInfoMap[i].CornerstoneLength,
			p.config.suiteInfoMap[i].AllowedPositions)
	}

	// creation of the entrypoints and cornerstones, places entrypoint and cornerstones
	p.CreateHeader()

	// creation of the encrypted payload
	p.encryptThenPadData(data)

	// converts everything to []byte, performs the XOR trick on the cornerstones
	p.placePayloadAndCornerstones()

	// computes and appends HMAC to a byte representation of a full purb
	p.addMAC()

	return nil
}

// Construct header computes and finds an appropriate placements for
// the Entrypoints and the Cornerstones
func (p *Purb) CreateHeader() {

	p.header = newEmptyHeader()

	p.createCornerstones()
	p.createEntryPoints()
	p.placeCornerstones()

	if p.config.simplifiedEntrypointsPlacement {
		p.placeEntrypointsSimplified()
	} else {
		p.placeEntrypoints()
	}
}

// Find what unique suites used by the Recipients, generate a private for each of these suites,
// and assign them to corresponding entry points
func (p *Purb) createCornerstones() {

	recipients := p.Recipients
	header := p.header

	for _, recipient := range recipients {

		// now create the said cornerstone. We advance if we already have a cornerstone for this suite
		// (LB->Kirill: can't two Recipients share the same suite?)
		if header.Cornerstones[recipient.SuiteName] != nil {
			continue
		}

		var keyPair *key.Pair
		for {
			// Generate a fresh SessionKey keyPair of a private SessionKey (scalar),
			// a public SessionKey (point), and hidden encoding of the public SessionKey
			keyPair = key.NewHidingKeyPair(recipient.Suite)

			if keyPair.Private == nil || keyPair.Public == nil {
				continue
			}
			if keyPair.Hiding == nil {
				continue
			}

			if keyPair.Hiding.HideLen() > p.config.suiteInfoMap[recipient.SuiteName].CornerstoneLength {
				purb.Logger.Fatal().Msgf("Length of an Elligator-encoded public key is not what we expect. It's %v",
					keyPair.Hiding.HideLen())
			}

			// key is OK!
			break
		}

		// register a new cornerstone for this suite
		cornerstone := p.newCornerStone(recipient.SuiteName, keyPair)
		header.Cornerstones[recipient.SuiteName] = cornerstone

		purb.Logger.Debug().Msgf("Created cornerstone[%v], value %v",
			recipient.SuiteName, cornerstone.Bytes)
	}
}

// Compute a shared secret per entrypoint used to encrypt it. It takes a public SessionKey
// of a recipient and multiplies it by fresh private SessionKey for a given cipher suite.
func (p *Purb) createEntryPoints() {
	// create an empty entrypoint per suite, indexed per suite
	for _, recipient := range p.Recipients {

		// fetch the cornerstone containing the freshly-generated public key for this suite
		cornerstone, found := p.header.Cornerstones[recipient.SuiteName]
		if !found {
			panic("no freshly generated private SessionKey exists for this ciphersuite")
		}

		// compute shared key for the entrypoint
		recipientKey := recipient.PublicKey
		senderKey := cornerstone.KeyPair.Private
		sharedKey := recipientKey.Mul(senderKey, recipientKey)

		if sharedKey == nil {
			panic("couldn't negotiate a shared DH SessionKey")
		}

		sharedBytes, err := sharedKey.MarshalBinary()
		if err != nil {
			panic("error" + err.Error())
		}

		// derive a shared secret using KDF
		sharedSecret := KDF("", sharedBytes)

		purb.Logger.Debug().Msgf("Shared secret with suite=%v, entrypoint value %v",
			recipient.SuiteName,
			sharedBytes)

		ep := &EntryPoint{
			Recipient:    recipient,
			SharedSecret: sharedSecret,
			Offset:       -1,
			Length:       p.config.suiteInfoMap[recipient.SuiteName].EntryPointLength,
		}

		// store entrypoint
		if len(p.header.EntryPoints[recipient.SuiteName]) == 0 {
			p.header.EntryPoints[recipient.SuiteName] = make([]*EntryPoint, 0)
		}

		p.header.EntryPoints[recipient.SuiteName] = append(
			p.header.EntryPoints[recipient.SuiteName], ep)
	}
}

func placeCornerstonesHelper(
	mainLayout *RegionReservationStruct,
	secondaryLayout *RegionReservationStruct,
	cornerstonesToPlace []*Cornerstone,
	placedCornerstones []*Cornerstone,
) []*Cornerstone {

	if len(cornerstonesToPlace) == 0 {
		purb.Logger.Debug().Msgf("Placed all cornerstones!")
		for _, c := range placedCornerstones {
			purb.Logger.Debug().Msgf("%v between %v and %v",
				c.SuiteName, c.Offset, c.EndPos)
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

		// find the first free position in the layout. We use the "secondaryLayout"
		// since secondary positions are *not* free for other cornerstones !
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

		purb.Logger.Debug().Msgf("Attempting position %v : %v for suite %v",
			startBit, endBit, cornerstone.SuiteName)

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
		res := placeCornerstonesHelper(mainLayout2, secondaryLayout2, remainingCornerstones,
			placedCornerstones2)
		if res != nil {
			// we found a solution, stop iterating
			return res
		}
	}

	return nil
}

// Writes cornerstone values to the first available entries of the ones assigned for use ciphersuites
func (p *Purb) placeCornerstones() {

	// To compute the "main layout", we use a secondary layout to keep track of things.
	// It is discarded at the end, and only helps computing mainLayout.
	// Two things to remember:
	// (1) every Suite has *multiple possible positions* for placing a cornerstone.
	// (2) when the PURB is finalized, the decoder can XOR *all possible positions*
	// (within the payload) to get the cornerstone
	// In principle, when we found the primary position for a suite,
	// we don't care what's gonna be in the remaining positions,
	// *but* it cannot be another cornerstone since we need to ensure
	// there is at least one degree of freedom to ensure property
	// (2). Hence, we place cornerstone where they don't collide
	// with other "things" in the primary payload (which is normal),
	// but also they cannot collide with other suite's allowed positions
	// (represented by the secondaryLayout).
	// On the other hand, other "things" (entrypoints, data),
	// can collide with the non-primary positions of the suites.
	// Final note: we start by placing the "longest" (bit-wise) cornerstone
	// since it has more chance to collide with something when placed.
	mainLayout := p.header.Layout
	secondaryLayout := NewRegionReservationStruct()

	// we first reserve the spot for the nonce
	mainLayout.Reserve(0, NonceLength, true, "nonce")
	secondaryLayout.Reserve(0, NonceLength, true, "nonce")

	cornerstonesToPlace := make([]*Cornerstone, 0)
	cornerstonesPlaced := make([]*Cornerstone, 0)
	for _, cornerstone := range p.header.Cornerstones {
		cornerstonesToPlace = append(cornerstonesToPlace, cornerstone)
	}

	placedCornerstones := placeCornerstonesHelper(mainLayout, secondaryLayout, cornerstonesToPlace,
		cornerstonesPlaced)

	if placedCornerstones == nil {
		panic("Could not find a mapping for placing the cornerstone, who designed the AllowedPositions ?!")
	}

	// for each cornerstone, register its position
	for _, cornerstone := range placedCornerstones {

		// ... in the cornerstone struct (which will be used when placing the entrypoints)
		p.header.Cornerstones[cornerstone.SuiteName].Offset = cornerstone.Offset
		p.header.Cornerstones[cornerstone.SuiteName].EndPos = cornerstone.EndPos

		if !mainLayout.Reserve(cornerstone.Offset, cornerstone.EndPos, true,
			cornerstone.SuiteName) {
			panic("I thought we had this position reserved")
		}

		purb.Logger.Debug().Msgf("Position for cornerstone %v is start %v, end %v",
			cornerstone.SuiteName, cornerstone.Offset, cornerstone.EndPos)
	}
}

// placeEntrypoints will find, place and reserve part of the header for the data
// All hash tables start after their cornerstone.
func (p *Purb) placeEntrypoints() {
	for _, cornerstone := range p.header.Cornerstones {
		suite := cornerstone.SuiteName
		for entrypointID, entrypoint := range p.header.EntryPoints[suite] {

			//hash table initialStartPos right after the cornerstone's offset-0
			initialStartPos := p.config.suiteInfoMap[suite].AllowedPositions[0] + p.config.suiteInfoMap[suite].CornerstoneLength

			//initial hash table size
			tableSize := 1
			positionFound := false
			intOfHashedValue := int(binary.BigEndian.Uint32(KDF("pos",
				entrypoint.SharedSecret))) // Large number to become a position
			var posInHashTable int

			// we start with a 1-sized hash table, try to place (and break on success), otherwise it grows by 2
			for !positionFound {

				// before doubling, consider hashTableCollisionLinearResolutionAttempts
				for j := 0; j < p.config.hashTableCollisionLinearResolutionAttempts; j++ {
					posInHashTable = (intOfHashedValue + j) % tableSize

					effectiveStartPos := initialStartPos + posInHashTable*entrypoint.Length
					effectiveEndPos := initialStartPos + (posInHashTable+1)*entrypoint.Length

					if p.header.Layout.Reserve(effectiveStartPos, effectiveEndPos, true,
						"hash"+strconv.Itoa(tableSize)) {
						p.header.EntryPoints[suite][entrypointID].Offset = effectiveStartPos
						positionFound = true

						purb.Logger.Debug().Msgf("Found position for entrypoint %v of suite %v, table size %v, linear %v, start %v, end %v",
							entrypointID, suite, tableSize, j, effectiveStartPos,
							effectiveEndPos)
						break
					}
				}

				if !positionFound {
					// If we haven't positionFound the entrypoint, update the hash table size and initialStartPos
					// initialStartPos = current hash table initialStartPos
					//                   + number of entries in the table* the length of each entrypoint
					initialStartPos += tableSize * entrypoint.Length
					tableSize *= 2
				}
			}
		}
	}
}

// placeEntrypoints will findAllRangesStrictlyBefore, place and reserve part of the header for the data.
// Does not use a hash table, put the points linearly
func (p *Purb) placeEntrypointsSimplified() {

	for _, cornerstone := range p.header.Cornerstones {
		suite := cornerstone.SuiteName
		for entryPointID, entrypoint := range p.header.EntryPoints[suite] {
			//hash table startPos right after the cornerstone's offset-0
			startPos := p.config.suiteInfoMap[suite].AllowedPositions[0] + p.config.suiteInfoMap[suite].CornerstoneLength

			for {
				if p.header.Layout.Reserve(startPos, startPos+entrypoint.Length, true,
					"hash"+strconv.Itoa(startPos)) {
					p.header.EntryPoints[suite][entryPointID].Offset = startPos
					endPos := startPos + entrypoint.Length

					purb.Logger.Debug().Msgf("Found position for entrypoint %v of suite %v, SIMPLIFIED, start %v, end %v",
						entryPointID, suite, startPos, endPos)

					//purb.Logger.Debug().Msgf("Placing entry at [%d-%d]", startPos, startPos+h.EntryPointLength)
					break
				}
				startPos += entrypoint.Length
			}
		}
	}
}

// Checks whether the provided byte range for MAC overlaps with any allowed cornerstone position
// for all the suites used in the PURB.
// Returns true in the case of overlap, and false otherwise.
func (p *Purb) macOverlapsWithAllowedPositions(macStart, macEnd int) bool {
	for _, cornerstone := range p.header.Cornerstones {
		cornerstoneLength := len(cornerstone.Bytes)
		for _, cornerstoneStartPos := range p.config.suiteInfoMap[cornerstone.SuiteName].AllowedPositions {
			cornerstoneEndPos := cornerstoneStartPos + cornerstoneLength
			if macStart < cornerstoneEndPos && macEnd > cornerstoneStartPos {
				purb.Logger.Warn().Msgf("Overlap with MAC detected: MAC from %v to %v, cornerstone from %v to %v. Going to "+
					"re-pad...", macStart, macEnd, cornerstoneStartPos, cornerstoneEndPos)
				return true
			}
		}
	}
	return false
}

// encryptThenPadData takes plaintext data as a byte slice,
// encrypts it using a stream cipher,
// then pads it with random bytes using Padmé
func (p *Purb) encryptThenPadData(data []byte) {
	payloadKey := KDF("enc", p.sessionKey)
	encryptedData := streamEncrypt(data, payloadKey)
	p.encryptedDataLen = len(encryptedData)
	purb.Logger.Debug().Msgf("Payload encrypted to %v (len %v)", encryptedData,
		len(encryptedData))

	p.payload = pad(encryptedData, p.header.Length()+MacAuthenticationTagLength)
	// If MAC overlaps with some allowed cornerstone position,
	// add one random byte to move to next allowed padding length
	for p.macOverlapsWithAllowedPositions(p.header.Length()+len(p.payload),
		p.header.Length()+len(p.payload)+MacAuthenticationTagLength) {
		randomByte := make([]byte, 1)
		random.Bytes(randomByte, random.New())
		p.payload = pad(append(p.payload, randomByte...),
			p.header.Length()+MacAuthenticationTagLength)
	}
	purb.Logger.Debug().Msgf("Encrypted payload padded from %v to %v bytes",
		len(encryptedData), len(p.payload))
}

// placePayloadAndCornerstones writes content of entrypoints and
// encrypted payloads into contiguous buffer
func (p *Purb) placePayloadAndCornerstones() {
	buffer := new(GrowableBuffer)

	// copy nonce
	if len(p.nonce) != 0 {
		region := buffer.growAndGetRegion(0, NonceLength)
		copy(region, p.nonce)

		purb.Logger.Debug().Msgf("Adding nonce in [%v:%v], value %v, len %v",
			0, NonceLength, p.nonce, len(p.nonce))

	}

	// copy cornerstones
	for _, cornerstone := range p.header.Cornerstones {
		startPos := cornerstone.Offset
		length := len(cornerstone.Bytes)
		endPos := cornerstone.Offset + length

		region := buffer.growAndGetRegion(startPos, endPos)
		copy(region, cornerstone.Bytes)

		purb.Logger.Debug().Msgf("Adding cornerstone in [%v:%v], value %v, len %v", startPos,
			endPos,
			cornerstone.Bytes, length)
	}

	// record payload start and payload end
	payloadStartOffset := make([]byte, StartOffsetLen)
	binary.BigEndian.PutUint32(payloadStartOffset, uint32(p.header.Length()))
	payloadEndOffset := make([]byte, EndOffsetLen)
	binary.BigEndian.PutUint32(payloadEndOffset, uint32(p.header.Length()+p.encryptedDataLen))

	// encrypt and copy entrypoints
	entrypointContent := append(p.sessionKey, payloadStartOffset...)
	entrypointContent = append(entrypointContent, payloadEndOffset...)
	for _, entrypointsPerSuite := range p.header.EntryPoints {
		for _, entrypoint := range entrypointsPerSuite {
			startPos := entrypoint.Offset
			endPos := startPos + entrypoint.Length
			region := buffer.growAndGetRegion(startPos, endPos)

			// we use shared secret as a seed to a Stream cipher
			entrypointKey := KDF("key", entrypoint.SharedSecret)
			encrypted, err := aeadEncrypt(entrypointContent, p.nonce, entrypointKey, nil, p.stream)
			if err != nil {
				purb.Logger.Fatal().Msg(err.Error())
			}
			copy(region, encrypted)

			purb.Logger.Debug().Msgf("Adding symmetric entrypoint in [%v:%v], plaintext value %v, encrypted value %v with key %v, len %v",
				startPos, endPos, entrypointContent, region, entrypoint.SharedSecret,
				len(entrypointContent))
		}
	}

	// Fill all unused parts of the header with random bits.
	fillRndFunction := func(low, high int) {
		region := buffer.growAndGetRegion(low, high)
		p.stream.XORKeyStream(region, region)

		purb.Logger.Debug().Msgf("Adding random bytes in [%v:%v]", low, high)
	}
	p.header.Layout.ScanFreeRegions(fillRndFunction, buffer.length())

	//purb.Logger.Debug().Msgf("Final length of header: %d", len(p.buf))
	//purb.Logger.Debug().Msgf("Random with header: %x", p.buf)

	// copy message into buffer

	purb.Logger.Debug().Msgf("Adding payload in [%v:%v], value %v, len %v", buffer.length(),
		buffer.length()+len(p.payload), p.payload, len(p.payload))
	buffer.append(p.payload)

	// sort cornerstone by order of apparition in the header
	cornerstones := make([]*Cornerstone, 0)
	for _, stone := range p.header.Cornerstones {
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

		for _, cornerstoneAllowedPos := range p.config.suiteInfoMap[cornerstone.SuiteName].AllowedPositions {
			endPos := cornerstoneAllowedPos + cornerstoneLength

			// check that we have data at non-primary positions to xor
			if endPos > buffer.length() {
				if cornerstoneAllowedPos > buffer.length() {
					// the position is fully outside the blob; we advanceIteratorUntil this cornerstone
					break
				}
				// the position is partially inside the blob; take only this
				endPos = buffer.length()
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

	p.byteRepresentation = buffer.toBytes()
}

// addMAC computes HMAC over a byte representation of a complete PURB
func (p *Purb) addMAC() {
	macKey := KDF("mac", p.sessionKey)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(p.byteRepresentation)
	tag := mac.Sum(nil)
	p.byteRepresentation = append(p.byteRepresentation, tag...)
}

func getMAC(blob []byte) []byte {
	return blob[len(blob)-MacAuthenticationTagLength:]
}

// ToBytes get the []byte representation of the PURB
func (p *Purb) ToBytes() []byte {
	return p.byteRepresentation
}

func (p *Purb) randomBytes(length int) []byte {
	buffer := make([]byte, length)
	random.Bytes(buffer, p.stream)
	return buffer
}

func newEmptyHeader() *Header {
	return &Header{
		EntryPoints:  make(map[string][]*EntryPoint),
		Cornerstones: make(map[string]*Cornerstone),
		Layout:       NewRegionReservationStruct(),
	}
}

func (p *Purb) newCornerStone(suiteName string, keyPair *key.Pair) *Cornerstone {

	hiddenBytes := keyPair.Hiding.HideEncode(p.stream)
	hiddenBytes2 := make([]byte, p.config.suiteInfoMap[suiteName].CornerstoneLength)

	// copy at the end
	copy(hiddenBytes2[len(hiddenBytes2)-len(hiddenBytes):], hiddenBytes[:])
	return &Cornerstone{
		SuiteName: suiteName,
		Offset:    -1,
		KeyPair:   keyPair, // do not call Hiding.HideEncode on this! it has been done already. Use bytes
		Bytes:     hiddenBytes2,
		SuiteInfo: p.config.suiteInfoMap[suiteName],
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
	length := NonceLength

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
