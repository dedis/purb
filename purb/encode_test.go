package purb

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/edwards"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"github.com/stretchr/testify/require"
	"fmt"
	"math"
)

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
	fmt.Println("=================TEST Generate Cornerstones=================")
	//info := createInfo()
	h := NewEmptyHeader()
	si := createInfo(3)
	decoders := createDecoders(6, si)
	h.genCornerstones(decoders, si, random.Stream)
	for _, stone := range h.SuitesToCornerstone {
		//fmt.Println(hex.EncodeToString(stone.Encoded))
		require.Equal(t, len(stone.Encoded), KEYLEN)
		require.NotEqual(t, stone.Priv, nil)
		require.NotEqual(t, stone.Pub, nil)
	}
}

func TestPurb_ConstructHeader(t *testing.T) {
	fmt.Println("=================TEST Construct Header=================")
	// Generate payload key and global nonce. It could be passed by an application above
	key := "key16key16key16!"
	nonce := "noncenonce12"
	purb, err := NewPurb([]byte(key), []byte(nonce))
	if err != nil {
		panic(err.Error())
	}
	si := createInfo(3)
	decs := createDecoders(6, si)
	purb.ConstructHeader(decs, si, STREAM, false, random.Stream)
	//fmt.Println("Content of the entries:")
	//for _, cell := range purb.Header.Layout {
	//	fmt.Println(hex.EncodeToString(cell))
	//}
}

func TestPurb_Write(t *testing.T) {
	fmt.Println("=================TEST PURB Write=================")
	key := "key16key16key16!"
	nonce := "noncenonce12"
	purb, err := NewPurb([]byte(key), []byte(nonce))
	if err != nil {
		panic(err.Error())
	}
	si := createInfo(3)
	decs := createDecoders(6, si)
	data := []byte("gorilla")
	// Normal
	purb.ConstructHeader(decs, si, STREAM, false, random.Stream)
	purb.PadThenEncryptData(data, random.Stream)
	purb.Write(si, STREAM, random.Stream)
	// Simplified
	purb, err = NewPurb([]byte(key), []byte(nonce))
	if err != nil {
		panic(err.Error())
	}
	purb.ConstructHeader(decs, si, STREAM, true, random.Stream)
	purb.PadThenEncryptData(data, random.Stream)
	purb.Write(si, STREAM, random.Stream)

}

func createInfo(N int) SuiteInfoMap {
	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := NONCE_LEN
		for i:=0; i<limit; i++ {
			positions[k][i] = floor + k % int(math.Pow(2, float64(i))) * KEYLEN
			floor += int(math.Pow(2, float64(i))) * KEYLEN
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[edwards.NewAES128SHA256Ed25519(true).String()+suffixes[i]] = &SuiteInfo{
			Positions: positions[i], KeyLen: KEYLEN,}
	}

	return info
}

func createDecoders(n int, si SuiteInfoMap) []Decoder {
	type suite struct {
		Name string
		Value abstract.Suite
	}
	decs := make([]Decoder, 0)
	suites := make([]suite, 0)
	for name := range si {
		suites = append(suites, suite{name, edwards.NewAES128SHA256Ed25519(true)})
	}
	//suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true)}
	for i := 0; i < n; i++ {
		for _, suite := range suites {
			pair := config.NewKeyPair(suite.Value)
			decs = append(decs, Decoder{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Secret})
		}
	}
	return decs
}
