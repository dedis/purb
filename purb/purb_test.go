package purb

import (
	"log"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/group/curve25519"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestGenCornerstones(t *testing.T) {
	infoMap := getDummySuiteInfo(3)
	purb := NewPurb(
		infoMap,
		false,
		random.New(),
	)

	purb.Recipients = createRecipients(6, 1, infoMap)
	purb.header = newEmptyHeader()

	purb.createCornerstones()

	for _, stone := range purb.header.Cornerstones {
		require.Equal(t, stone.KeyPair.Hiding.HideLen(), infoMap[stone.SuiteName].CornerstoneLength)
		require.NotEqual(t, stone.KeyPair.Private, nil)
		require.NotEqual(t, stone.KeyPair.Public, nil)
	}
}

func TestPurbCreation(t *testing.T) {
	data := []byte("SomeInfo")

	infoMap := getDummySuiteInfo(2)
	purb := NewPurb(
		infoMap,
		false,
		random.New(),
	)

	purb.Recipients = createRecipients(1, 1, infoMap)
	err := purb.Encode(data)

	if err != nil {
		t.Error(err)
	}

	log.Println(purb.VisualRepresentation(true))
}

func TestEncodeDecode(t *testing.T) {
	maxSuites := 10
	maxRecipients := 10

	if testing.Short() {
		maxSuites = 3
		maxRecipients = 3
	}

	data := []byte("01234567")

	for nSuites := 1; nSuites < maxSuites; nSuites++ {
		for nRecipients := 1; nRecipients < maxRecipients; nRecipients++ {
			log.Println("Testing for", nSuites, "suites and", nRecipients, "Recipients")
			suitesInfo := getDummySuiteInfo(nSuites)

			// try encode
			purb := NewPurb(
				suitesInfo,
				false,
				random.New(),
			)

			purb.Recipients = createRecipients(nRecipients, nSuites, suitesInfo)
			err := purb.Encode(data)
			if err != nil {
				log.Fatal(err)
			}

			// try parse to bits
			blob := purb.ToBytes()

			// print for fun
			//log.Println(purb.visualRepresentation(true))

			// try decode
			for recipientsID := 0; recipientsID < nRecipients; recipientsID++ {
				log.Println("Decrypting for recipient", recipientsID)
				success, message, err := purb.Decode(blob)
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
	maxSuites := 10
	maxRecipients := 10

	if testing.Short() {
		maxSuites = 3
		maxRecipients = 3
	}

	data := []byte("01234567")

	for nSuites := 1; nSuites < maxSuites; nSuites++ {
		for nRecipients := 1; nRecipients < maxRecipients; nRecipients++ {

			log.Println("Testing for", nSuites, "suites and", nRecipients, "Recipients")
			suitesInfo := getDummySuiteInfo(nSuites)

			// try encode
			purb := NewPurb(
				suitesInfo,
				true,
				random.New(),
			)

			purb.Recipients = createRecipients(nRecipients, nSuites, suitesInfo)
			err := purb.Encode(data)
			if err != nil {
				log.Fatal(err)
			}

			// try parse to bits
			blob := purb.ToBytes()

			// print for fun
			//log.Println(purb.visualRepresentation(true))

			// try decode
			for recipientsID := 0; recipientsID < nRecipients; recipientsID++ {
				log.Println("Decrypting for recipient", recipientsID)

				success, message, err := purb.Decode(blob)
				if err != nil {
					log.Fatal(err)
				}

				require.True(t, success)
				require.Equal(t, data, message)
			}
		}
	}
}

func TestMacCornerstoneOverlap(t *testing.T) {
	data := []byte("SomeInfo")
	suitesInfo := getDummySuiteInfoWithMultipleSuitePositions()
	recipients := createRecipients(1, 1, suitesInfo)

	log.Println("Testing the resolution of a MAC and a cornerstone position overlap")

	purb := NewPurb(
		suitesInfo,
		false,
		random.New(),
	)

	purb.Recipients = recipients

	err := purb.Encode(data)
	if err != nil {
		t.Error(err)
	}
	blob := purb.ToBytes()

	// try decode
	success, message, err := purb.Decode(blob)
	if err != nil {
		log.Fatal(err)
	}
	require.True(t, success)
	require.Equal(t, data, message)
}

func getDummySuiteInfo(N int) SuiteInfoMap {

	entryPointLen := 16 + 4 + 4 + 16
	cornerstoneLen := 32
	aeadNonceLen := 12

	// we create N times the same suite
	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}

	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := aeadNonceLen
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*cornerstoneLen
			floor += int(math.Pow(2, float64(i))) * cornerstoneLen
		}
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			AllowedPositions:  positions[i],
			CornerstoneLength: cornerstoneLen,
			EntryPointLength:  entryPointLen,
		}
	}

	return info
}

func getDummySuiteInfoWithMultipleSuitePositions() SuiteInfoMap {
	entryPointLen := 16 + 4 + 4 + 16
	cornerstoneLen := 32
	//aeadNonceLen := 12

	// we create N times the same suite
	info := make(SuiteInfoMap)
	positions := []int{0, 2 * cornerstoneLen, 3 * cornerstoneLen, 5 * cornerstoneLen}

	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &SuiteInfo{
		AllowedPositions:  positions,
		CornerstoneLength: cornerstoneLen,
		EntryPointLength:  entryPointLen,
	}

	return info
}

func createRecipients(n int, numberOfSuites int, si SuiteInfoMap) []Recipient {
	type suite struct {
		Name  string
		Value Suite
	}
	decs := make([]Recipient, 0)
	suites := make([]suite, 0)
	for name := range si {
		if len(suites) >= numberOfSuites {
			break
		}
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for i := 0; i < n; i++ {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, Recipient{
				SuiteName:  suite.Name,
				Suite:      suite.Value,
				PublicKey:  pair.Public,
				PrivateKey: pair.Private,
			})
		}
	}
	return decs
}
