package purb

import (
	"testing"
	"fmt"
	"gopkg.in/dedis/crypto.v0/edwards"
	"gopkg.in/dedis/crypto.v0/random"
	"encoding/hex"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"github.com/stretchr/testify/require"
)

func TestPurb(t *testing.T) {
	//info := createInfo()
	//fmt.Println(info[edwards.NewAES128SHA256Ed25519(false).String()].Positions)
	//h := NewEmptyHeader()
	//h.Fill()
}

func TestPurb_EncryptPayload(t *testing.T) {
	payload := []byte("Test AEAD")
	h := NewEmptyHeader()
	p := NewPurb(h, payload)
	p.Header.SuitesToCornerstone[edwards.NewAES128SHA256Ed25519(true).String()] = &Cornerstone{}
	//p.Header.SuitesToCornerstone[ed25519.NewAES128SHA256Ed25519(true).String()] = &Cornerstone{}
	p.EncryptPayload(random.Stream)
	fmt.Println("Text length: ", len(payload))
	fmt.Printf("Suite: %s \n Key: %s \n Content: %s \n Size: %d \n", p.EncPayloads[0].Suite,
		hex.EncodeToString(p.EncPayloads[0].Key), hex.EncodeToString(p.EncPayloads[0].Content), p.EncPayloads[0].Size)
}

func TestHeader_GenCornerstones(t *testing.T) {
	//info := createInfo()
	h := NewEmptyHeader()
	decoders := createDecoders()
	for _, d := range decoders {
		h.Entries = append(h.Entries, NewEntry(d, nil))
	}
	h.GenCornerstones(random.Stream)
	for _, stone := range h.SuitesToCornerstone {
		require.Equal(t, len(stone.encoded), 40)
		require.NotEqual(t, stone.priv, nil)
		require.NotEqual(t, stone.pub, nil)
	}
}

func createInfo() *SuiteInfoMap {
	info := make(SuiteInfoMap)
	info[edwards.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
		Positions: []int{0, 32, 96},
		KeyLen:    KEYLEN,}
	//info[ed25519.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
	//	Positions: []int{0, 32, 128},
	//	KeyLen:    KEYLEN,}
	return &info
}

func createDecoders() []Decoder {
	var decs []Decoder
	//suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true), ed25519.NewAES128SHA256Ed25519(true)}
	suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true)}
	for _, suite := range suites {
		pair := config.NewKeyPair(suite)
		decs = append(decs, Decoder{suite, pair.Public})
	}
	return decs
}
