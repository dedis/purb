package purbs

import (
	"fmt"
	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/nikirill/crypto/purb"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestHeader_GenCornerstones(t *testing.T) {
	fmt.Println("=================TEST Generate Cornerstones=================")
	//info := createInfo()
	h := NewEmptyHeader()
	si := createInfo(3)
	decoders := createDecoders(6, si)
	h.genCornerstones(decoders, si, random.New())
	for _, stone := range h.SuitesToCornerstone {
		//fmt.Println(hex.EncodeToString(stone.Encoded))
		require.Equal(t, stone.KeyPair.Hiding.HideLen(), KEYLEN)
		require.NotEqual(t, stone.KeyPair.Private, nil)
		require.NotEqual(t, stone.KeyPair.Public, nil)
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
	purb.ConstructHeader(decs, si, STREAM, false, random.New())
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
	purb.ConstructHeader(decs, si, STREAM, false, random.New())
	purb.PadThenEncryptData(data, random.New())
	purb.Write(si, STREAM, random.New())
	// Simplified
	purb, err = NewPurb([]byte(key), []byte(nonce))
	if err != nil {
		panic(err.Error())
	}
	purb.ConstructHeader(decs, si, STREAM, true, random.New())
	purb.PadThenEncryptData(data, random.New())
	purb.Write(si, STREAM, random.New())

}

func createInfo(N int) SuiteInfoMap {
	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := NONCE_LEN
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*purb.KEYLEN
			floor += int(math.Pow(2, float64(i))) * purb.KEYLEN
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			Positions: positions[i], KeyLen: purb.KEYLEN}
	}

	return info
}

func createDecoders(n int, si SuiteInfoMap) []Decoder {
	type suite struct {
		Name  string
		Value Suite
	}
	decs := make([]Decoder, 0)
	suites := make([]suite, 0)
	for name := range si {
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for i := 0; i < n; i++ {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, Decoder{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}
