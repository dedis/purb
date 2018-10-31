package purbs

import (
	"encoding/binary"
	"sort"
)

// ToBytes writes content of entrypoints and encrypted payloads into contiguous buffer
func (purb *Purb) ToBytes() []byte {

	buffer := new(GrowableBuffer)

	// copy nonce
	if len(purb.Nonce) != 0 {
		region := buffer.growAndGetRegion(0, AEAD_NONCE_LENGTH)
		copy(region, purb.Nonce)
	}

	// copy cornerstones
	for _, stone := range purb.Header.Cornerstones {
		region := buffer.growAndGetRegion(stone.Offset, stone.Offset+stone.KeyPair.Hiding.HideLen())
		copy(region, stone.KeyPair.Hiding.HideEncode(purb.stream))
	}

	// encrypt and copy entrypoints
	payloadOffset := make([]byte, OFFSET_POINTER_LEN)
	binary.BigEndian.PutUint32(payloadOffset, uint32(purb.Header.Length))

	entrypointContent := append(purb.PayloadKey, payloadOffset...)
	for _, entrypointsPerSuite := range purb.Header.EntryPoints {
		for _, entrypoint := range entrypointsPerSuite {
			switch purb.symmKeyWrapType {
				case STREAM:
					// we use shared secret as a seed to a stream cipher
					xof := entrypoint.Recipient.Suite.XOF(entrypoint.SharedSecret)
					startPos := entrypoint.Offset
					endPos := startPos + purb.Header.EntryPointLength

					region := buffer.growAndGetRegion(startPos, endPos)
					xof.XORKeyStream(region, entrypointContent)
				case AEAD:
					panic("not implemented")
			}
		}
	}

	// Fill all unused parts of the header with random bits.
	fillRndFunction := func(lo, hi int) {
		region := buffer.growAndGetRegion(lo, hi)
		purb.stream.XORKeyStream(region, region)
	}
	purb.Header.Layout.scanFree(fillRndFunction, buffer.length())

	//log.Printf("Final length of header: %d", len(p.buf))
	//log.Printf("Random with header: %x", p.buf)

	// copy message into buffer
	buffer.append(purb.Payload)

	// XOR each cornerstone with the data in its non-primary positions and save as the cornerstone value
	cornerstones := make([]*Cornerstone, 0)
	for _, stone := range purb.Header.Cornerstones {
		cornerstones = append(cornerstones, stone)
	}
	sort.Slice(cornerstones, func(i, j int) bool {
		return cornerstones[i].Offset < cornerstones[j].Offset
	})
	for _, cornerstone := range cornerstones {

		cornerstoneLength := cornerstone.KeyPair.Hiding.HideLen()
		corbuf := make([]byte, cornerstoneLength)

		for _, offset := range purb.infoMap[cornerstone.SuiteName].AllowedPositions {
			stop := offset + cornerstoneLength
			// check that we have data at non-primary positions to xor
			if stop > buffer.length() {
				if offset > buffer.length() {
					break
				} else {
					stop = buffer.length()
				}
			}
			tmp := buffer.slice(offset, stop)

			for b := 0; b < cornerstoneLength; b++ {
				corbuf[b] ^= tmp[b]
			}
		}
		// copy the result of XOR to the primary position
		startPos := cornerstone.Offset
		endPos := startPos + cornerstoneLength
		buffer.copyInto(startPos, endPos, corbuf)
	}
	return buffer.toBytes()
}
