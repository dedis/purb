package purb

import (
	"math"

	"go.dedis.ch/kyber/v3/util/random"
)

// Pads a message with random bytes as defined by Padmé.
// 'other' is a number of additional bytes in purb (header, nonce, mac)
// that need to be taken into account when computing the amount of padding.
func pad(msg []byte, other int) []byte {
	var paddedMsg []byte
	msgLen := uint64(len(msg) + other) // Length in bytes
	padLen := paddingLength(msgLen)

	pad := getRandomBytes(padLen)
	paddedMsg = append(msg, pad...)
	return paddedMsg
}

// UnPads a padded message
func unPad(msg []byte, end int) []byte {
	return msg[:end]
}

// Computes amount of padding needed
func paddingLength(msgLen uint64) int {
	var mask, paddingNeeded, paddedMsgLen uint64
	zeroBytes := zeroBytesNeeded(msgLen)
	//Generate a mask that we use to isolate the zeroBits bits of the length (e.g., 11111)
	mask = (1 << zeroBytes) - 1
	// How much we need to pad to obtain the required number of zero bits at the end
	paddedMsgLen = (msgLen + mask) & ^mask
	paddingNeeded = paddedMsgLen - msgLen
	return int(paddingNeeded)
}

// Returns number of bytes at the end that are required to be zero in the binary
// representation of message length l.
func zeroBytesNeeded(l uint64) uint64 {
	// the corner case of 1-byte message
	if l == 1 {
		return uint64(0)
	}
	E := math.Floor(math.Log2(float64(l)))
	S := math.Floor(math.Log2(E)) + 1
	return uint64(E - S)
}

// Generates an array of random bytes of the required length
func getRandomBytes(l int) []byte {
	b := make([]byte, l)
	random.Bytes(b, random.New())
	return b
}
