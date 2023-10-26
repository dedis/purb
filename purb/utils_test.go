package purb

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStreamCipher(t *testing.T) {
	data := []byte("very secret information")
	key := []byte("full of entropy")

	ctxt := streamEncrypt(data, key)
	log.Println("Encrypted stream output: ", ctxt)
	plxt := streamDecrypt(ctxt, key)

	require.Equal(t, data, plxt)
}
