package purb

import (
	"testing"
	"fmt"
	"gopkg.in/dedis/crypto.v0/random"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	fmt.Println("=================TEST PURB Decode=================")
	si := createInfo()
	decs := createDecoders(10)
	data := []byte("gorilla here, gorilla there, I am not going anywhere")
	// Normal
	blob, err := MakePurb(data, decs, si, STREAM, false, random.Stream)
	if err != nil {
		panic(err.Error())
	}
	success, message, err := Decode(blob, &decs[5], STREAM, false, si)
	if err != nil {
		panic(err.Error())
	}
	require.True(t, success)
	require.Equal(t, data, message)

	// Simplified
	blob, err = MakePurb(data, decs, si, STREAM, true, random.Stream)
	if err != nil {
		panic(err.Error())
	}
	success, message, err = Decode(blob, &decs[5], STREAM, true, si)
	if err != nil {
		panic(err.Error())
	}
	require.True(t, success)
	require.Equal(t, data, message)
}
