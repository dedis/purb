package purbs

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPad(t *testing.T) {
	msg := []byte("this is a message that is supposed to be padded with 5 random bytes") // 67 bytes
	result := pad(msg, 0)
	require.Equal(t, 72, len(result))
	// Now we add an overhead of 7 bytes representing the header
	headerLen := 7
	result = pad(msg, headerLen)
	require.Equal(t, 80, len(result)+headerLen)
}

func TestUnPad(t *testing.T) {
	var padLen int = 4
	msg := []byte("I am an unpadded message")
	msgPadded := append(msg, make([]byte, padLen)...)
	result := unPad(msgPadded, len(msg))
	require.Equal(t, msg, result)
}

func TestBitsToZero(t *testing.T) {
	require.Equal(t, 1, int(zeroBytesNeeded(8)))
	require.Equal(t, 1, int(zeroBytesNeeded(9)))
	require.Equal(t, 1, int(zeroBytesNeeded(10)))
}
