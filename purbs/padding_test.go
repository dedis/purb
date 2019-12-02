package purbs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPad(t *testing.T) {
	msg := []byte("this is a long message that is supposed to be padded by 0x80 and 3 zero bytes") // 77 bytes
	result := pad(msg, 0)
	require.Equal(t, 80, len(result))
	// Now we add an overhead of 7 bytes representing the header
	headerLen := 7
	result = pad(msg, headerLen)
	require.Equal(t, 88, len(result)+headerLen)
}

func TestUnPad(t *testing.T) {
	msg := []byte("I am an unpadded message")
	msgPadded := append(msg, STARTPADBYTE)
	msgPadded = append(msgPadded, make([]byte, 4)...)
	result := unPad(msgPadded)
	require.Equal(t, msg, result)
}

func TestBitsToZero(t *testing.T) {
	require.Equal(t, 1, int(zeroBytesNeeded(8)))
	require.Equal(t, 1, int(zeroBytesNeeded(9)))
	require.Equal(t, 1, int(zeroBytesNeeded(10)))
}
