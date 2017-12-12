package purb

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/edwards"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"github.com/stretchr/testify/require"
	"fmt"
	"encoding/hex"
)

//func TestPurb(t *testing.T) {
//	info := createInfo()
//	fmt.Println(info[edwards.NewAES128SHA256Ed25519(false).String()].Positions)
//	h := NewEmptyHeader()
//	h.Fill()
//}
//
//func TestPurb_EncryptPayload(t *testing.T) {
//	payload := []byte("Test AEAD")
//	h := NewEmptyHeader()
//	p := NewPurb(h, payload)
//	p.Header.SuitesToCornerstone[edwards.NewAES128SHA256Ed25519(true).String()] = &Cornerstone{}
//	//p.Header.SuitesToCornerstone[ed25519.NewAES128SHA256Ed25519(true).String()] = &Cornerstone{}
//	p.EncryptPayload(random.Stream)
//	fmt.Println("Text length: ", len(payload))
//	fmt.Printf("Key: %s \n Content: %s \n Size: %d \n",
//		hex.EncodeToString(p.Payload.Key), hex.EncodeToString(p.Payload.Content), p.Payload.Size)
//}

func TestHeader_GenCornerstones(t *testing.T) {
	//info := createInfo()
	h := NewEmptyHeader()
	decoders := createDecoders()
	for _, d := range decoders {
		h.Entries = append(h.Entries, NewEntry(d, nil))
	}
	h.GenCornerstones(random.Stream)
	for _, stone := range h.SuitesToCornerstone {
		//fmt.Println(hex.EncodeToString(stone.Encoded))
		require.Equal(t, len(stone.Encoded), KEYLEN)
		require.NotEqual(t, stone.Priv, nil)
		require.NotEqual(t, stone.Pub, nil)
	}
}

func TestPurb_ConstructHeader(t *testing.T) {
	fmt.Println("========TEST Construct Header=========")
	// Generate payload key and global nonce. It could be passed by an application above
	key := "key16key16key16!"
	nonce := "noncenonce12"
	purb, err := NewPurb([]byte(key), []byte(nonce))
	if err != nil {
		panic(err.Error())
	}
	si := createInfo()
	decs := createDecoders()
	purb.ConstructHeader(decs, si, random.Stream)
	fmt.Println("Content of the entries:")
	for _, cell := range purb.Header.Layout {
		fmt.Println(hex.EncodeToString(cell))
	}
}

func createInfo() SuiteInfoMap {
	info := make(SuiteInfoMap)
	info[edwards.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
		Positions: []int{0*ENTRYLEN, 1*ENTRYLEN, 3*ENTRYLEN},
		KeyLen:    KEYLEN,}
	//info[ed25519.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
	//	Positions: []int{0, 40, 160},
	//	KeyLen:    KEYLEN,}
	return info
}

func createDecoders() []Decoder {
	var decs []Decoder
	//suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true), ed25519.NewAES128SHA256Ed25519(true)}
	suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true)}
	for _, suite := range suites {
		for i:=0; i<3; i++ {
			pair := config.NewKeyPair(suite)
			decs = append(decs, Decoder{suite, pair.Public})
		}
	}
	return decs
}
