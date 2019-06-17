package purbs

import (
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
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
