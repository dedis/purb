package purbs

// A simple []byte slice with helpful wrapper
type GrowableBuffer struct {
	buffer []byte
}

// Grow the message buffer to include the byteRangeForAllowedPositionIndex from startByte to endByte,
// and return a slice representing that byteRangeForAllowedPositionIndex.
func (gb *GrowableBuffer) growAndGetRegion(startByte, endByte int) []byte {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}

	if len(gb.buffer) < endByte {
		newBuffer := make([]byte, endByte)
		copy(newBuffer, gb.buffer)
		gb.buffer = newBuffer
	}
	return gb.buffer[startByte:endByte]
}

func (gb *GrowableBuffer) length() int {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}
	return len(gb.buffer)
}

func (gb *GrowableBuffer) append(data []byte) {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}
	gb.buffer = append(gb.buffer, data...)
}

func (gb *GrowableBuffer) slice(low, high int) []byte {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}
	return gb.buffer[low:high]
}

func (gb *GrowableBuffer) copyInto(low, high int, data []byte) {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}
	copy(gb.buffer[low:high], data)
}

func (gb *GrowableBuffer) toBytes() []byte {
	if gb.buffer == nil {
		gb.buffer = make([]byte, 0)
	}
	return gb.buffer
}
