package purbs

import (
	"bytes"
	"math"
)

// For the padding we use scheme ISO/IEC 7816-4:2005 as the most space efficient.
// The first byte of padding is a mandatory byte valued '80' (Hexadecimal) followed,
// if needed, by 0 to N-1 bytes set to '00', until the end of the block is reached.
//Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
//... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
//The next example shows a padding of just one byte
//... | DD DD DD DD DD DD DD DD | DD DD DD DD DD DD DD 80 |
// https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4

// The byte value that signals that it's the start of padding.
const STARTPADBYTE = 0x80

// Pads a message according the defined scheme.
// 'other' is a number of additional bytes in purb (header, nonce, mac)
// that need to be taken into account when computing the amount of padding.
func pad(msg []byte, other int) []byte {
	var paddedMsg []byte
	// STARTPADBYTE must be always present so we append it first and then compute
	// amount of zero padding needed
	msg = append(msg, STARTPADBYTE)
	msgLen := 8 * (uint64(len(msg) + other)) // Length in bits
	padLen := paddingLength(msgLen)
	// Convert padding length to the number of bytes needed
	if padLen < 8 && padLen != 0 {
		padLen = 1
	} else {
		padLen = int(math.Ceil(float64(padLen) / 8))
	}
	// Padding the message with zeros
	pad := make([]byte, padLen)
	paddedMsg = append(msg, pad...)
	return paddedMsg
}

// UnPads a padded message
func unPad(msg []byte) []byte {
	stop := bytes.LastIndexByte(msg, STARTPADBYTE)
	return msg[:stop]
}

// Computes amount of padding needed
func paddingLength(msgLen uint64) int {
	var mask, paddingNeeded uint64
	zeroBits := zeroBitsNeeded(msgLen)
	//Generate a mask that we use to isolate the zeroBits bits of the length (e.g., 11111)
	mask = (1 << zeroBits) - 1
	paddingNeeded = 1 << zeroBits
	// How much we need to pad to obtain the required number of zero bits at the end
	paddingNeeded = paddingNeeded - (msgLen & mask)
	return int(paddingNeeded)
}

// Returns number of bits at the end that are required to be zero in the binary
// representation of message length l.
func zeroBitsNeeded(l uint64) uint64 {
	E := math.Floor(math.Log2(float64(l)))
	S := math.Floor(math.Log2(E)) + 1
	return uint64(E - S)
}
