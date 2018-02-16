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
	decs := createDecoders()
	data := []byte("gorilla")
	blob, err := MakePurb(data, decs, si, random.Stream)
	if err != nil {
		panic(err.Error())
	}
	success, message, err := Decode(blob, &decs[3], si)
	if err != nil {
		panic(err.Error())
	}
	require.True(t, success)
	require.Equal(t, data, message)
}
