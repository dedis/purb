package purbs

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPad(t *testing.T) {
	msg := []byte("this is a long message that is supposed to be padded by 0x80 and 3 zero bytes")
	result := pad(msg, 0)
	//fmt.Println("Unpaded bit length ", 8*len(msg))
	//fmt.Printf("Padded bit length %d \nArray is %v\n", 8*len(result), result)
	require.Equal(t, 640, 8*len(result))

	// Now we add an overhead of 7 bytes representing the header
	result = pad(msg, 7)
	require.Equal(t, 704, 8*(len(result)+7))
}

func TestUnPad(t *testing.T) {
	msg := []byte("I am an unpadded message")
	msgPadded := append(msg, STARTPADBYTE)
	msgPadded = append(msgPadded, make([]byte, 4)...)
	result := unPad(msgPadded)
	require.Equal(t, msg, result)
	//fmt.Printf("Result: %s\n", result)
}
