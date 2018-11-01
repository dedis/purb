package purbs

import (
	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestGenCornerstones(t *testing.T) {
	purb := &Purb{
		Nonce:      nil,
		Header:     nil,
		Payload:    nil,
		PayloadKey: nil,

		isVerbose:       true,
		recipients:      nil,
		infoMap:         nil,
		symmKeyWrapType: STREAM,
		stream:          random.New(),
	}

	purb.infoMap = getDummySuiteInfo(3)
	purb.recipients = createRecipients(6, purb.infoMap)

	purb.Header = newEmptyHeader()
	switch purb.symmKeyWrapType {
	case STREAM:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN
	case AEAD:
		purb.Header.EntryPointLength = SYMMETRIC_KEY_LENGTH + OFFSET_POINTER_LEN + MAC_AUTHENTICATION_TAG_LENGTH
	}

	purb.createCornerstonesAndEntrypoints()

	for _, stone := range purb.Header.Cornerstones {
		require.Equal(t, stone.KeyPair.Hiding.HideLen(), CORNERSTONE_LENGTH)
		require.NotEqual(t, stone.KeyPair.Private, nil)
		require.NotEqual(t, stone.KeyPair.Public, nil)
	}
}

func TestPurbCreation(t *testing.T) {

	data := []byte("SomeInfo")
	infoMap := getDummySuiteInfo(2)
	recipients := createRecipients(1, infoMap)

	purb, err := PURBEncode(data, recipients, infoMap, STREAM, random.New(), true, true)

	if err != nil {
		t.Error(err)
	}

	log.Lvl1(purb.VisualRepresentation(true))
}

func TestEncodeDecode(t *testing.T) {

	simplified := false
	verbose := false
	stream := random.New()
	keyWrapperType := STREAM

	maxSuites := 10
	maxRecipients := 10

	if testing.Short() {
		maxSuites = 3
		maxRecipients = 3
	}

	data := []byte("01234567")

	for nSuites := 1; nSuites < maxSuites; nSuites++ {
		for nRecipients := 1; nRecipients < maxRecipients; nRecipients++ {

			log.Lvl1("Testing for", nSuites, "suites and", nRecipients, "recipients")
			suitesInfo := getDummySuiteInfo(nSuites)
			recipients := createRecipients(nRecipients, suitesInfo)

			// try encode
			purb, err := PURBEncode(data, recipients, suitesInfo, keyWrapperType, stream, simplified, verbose)
			if err != nil {
				log.Fatal(err)
			}

			// try parse to bits
			blob := purb.ToBytes()

			// print for fun
			//log.Lvl1(purb.visualRepresentation(true))

			// try decode
			for recipientsID := 0; recipientsID < nRecipients; recipientsID++ {
				log.Lvl1("Decrypting for recipient", recipientsID)
				success, message, err := PURBDecode(blob, &recipients[0], keyWrapperType, simplified, suitesInfo, verbose)
				if err != nil {
					log.Fatal(err)
				}

				require.True(t, success)
				require.Equal(t, data, message)
			}
		}
	}
}

func TestEncodeDecodeSimplified(t *testing.T) {
	simplified := true
	verbose := false
	stream := random.New()
	keyWrapperType := STREAM

	maxSuites := 10
	maxRecipients := 10

	if testing.Short() {
		maxSuites = 3
		maxRecipients = 3
	}

	data := []byte("01234567")

	for nSuites := 1; nSuites < maxSuites; nSuites++ {
		for nRecipients := 1; nRecipients < maxRecipients; nRecipients++ {

			log.Lvl1("Testing for", nSuites, "suites and", nRecipients, "recipients")
			suitesInfo := getDummySuiteInfo(nSuites)
			recipients := createRecipients(nRecipients, suitesInfo)

			// try encode
			purb, err := PURBEncode(data, recipients, suitesInfo, keyWrapperType, stream, simplified, verbose)
			if err != nil {
				log.Fatal(err)
			}

			// try parse to bits
			blob := purb.ToBytes()

			// print for fun
			//log.Lvl1(purb.visualRepresentation(true))

			// try decode
			for recipientsID := 0; recipientsID < nRecipients; recipientsID++ {
				log.Lvl1("Decrypting for recipient", recipientsID)
				success, message, err := PURBDecode(blob, &recipients[0], keyWrapperType, simplified, suitesInfo, verbose)
				if err != nil {
					log.Fatal(err)
				}

				require.True(t, success)
				require.Equal(t, data, message)
			}
		}
	}
}

func getDummySuiteInfo(N int) SuiteInfoMap {

	// we create N times the same suite
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
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			AllowedPositions: positions[i], CornerstoneLength: CORNERSTONE_LENGTH}
	}

	return info
}

func createRecipients(n int, si SuiteInfoMap) []Recipient {
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
