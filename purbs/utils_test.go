package purbs

import (
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStreamCipher(t *testing.T) {
	data := []byte("very secret information")
	key := []byte("full of entropy")

	ctxt := streamEncrypt(data, key)
	log.Lvl2("Encrypted stream output: ", ctxt)
	plxt := streamDecrypt(ctxt, key)

	require.Equal(t, data, plxt)
}
