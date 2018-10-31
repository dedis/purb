package purbs

import (
	"fmt"
	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestGenCornerstones(t *testing.T) {
	purb := &Purb{
		Nonce:      nil,
		Header: nil,
		Payload: nil,
		PayloadKey: nil,

		isVerbose: true,
		recipients: nil,
		infoMap: nil,
		symmKeyWrapType: STREAM,
		stream: random.New(),
	}

	purb.infoMap = createInfo(3)
	purb.recipients = createDecoders(6, purb.infoMap)

	purb.Header = newEmptyHeader()
	switch purb.symmKeyWrapType {
	case STREAM:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	purb.createCornerStoneAndEntryPoints()

	for _, stone := range purb.Header.Cornerstones {
		//fmt.Println(hex.EncodeToString(stone.Encoded))
		require.Equal(t, stone.KeyPair.Hiding.HideLen(), CORNERSTONE_LENGTH)
		require.NotEqual(t, stone.KeyPair.Private, nil)
		require.NotEqual(t, stone.KeyPair.Public, nil)
	}
}

func TestPurbCreation(t *testing.T) {

	data := []byte("SomeInfo")
	infoMap := createInfo(3)
	recipients := createDecoders(6, infoMap)

	purb, err := PURBEncode(data, recipients, infoMap, STREAM, random.New(), true, true)

	if err != nil {
		t.Error(err)
	}

	fmt.Printf("%+v\n", purb)
}

func TestEncodeDecode(t *testing.T) {
	si := createInfo(1)
	decs := createDecoders(3, si)
	data := []byte("gorilla here, gorilla there, I am not going anywhere")
	// Normal
	blob, err := PURBEncode(data, decs, si, STREAM, random.New(), false, true)
	if err != nil {
		panic(err.Error())
	}
	success, message, err := PURBDecode(blob, &decs[5], STREAM, false, si)
	if err != nil {
		panic(err.Error())
	}
	require.True(t, success)
	require.Equal(t, data, message)
}

func TestEncodeDecodeSimplified(t *testing.T) {
	si := createInfo(3)
	decs := createDecoders(10, si)
	data := []byte("gorilla here, gorilla there, I am not going anywhere")

	// Simplified
	blob, err := PURBEncode(data, decs, si, STREAM, random.New(), true, true)
	if err != nil {
		panic(err.Error())
	}
	success, message, err := PURBDecode(blob, &decs[5], STREAM, true, si)
	fmt.Println(success, message, err)
	if err != nil {
		panic(err.Error())
	}
	require.True(t, success)
	require.Equal(t, data, message)
}


func createInfo(N int) SuiteInfoMap {
	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := AEAD_NONCE_LENGTH
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*CORNERSTONE_LENGTH
			floor += int(math.Pow(2, float64(i))) * CORNERSTONE_LENGTH
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			AllowedPositions: positions[i], KeyLen: CORNERSTONE_LENGTH}
	}

	return info
}

func createDecoders(n int, si SuiteInfoMap) []Recipient {
	type suite struct {
		Name  string
		Value Suite
	}
	decs := make([]Recipient, 0)
	suites := make([]suite, 0)
	for name := range si {
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for i := 0; i < n; i++ {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, Recipient{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}
