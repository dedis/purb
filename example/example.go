package main

import (
	"encoding/hex"
	"fmt"

	"github.com/dedis/purb/purbs"
	"go.dedis.ch/kyber/v3/group/curve25519"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
)

func main() {
	// this is public and fixed across all purbs
	suitesInfo := getDummySuiteInfo()
	verbose := false
	simplified := false // when "true", does not use hash tables (but linear mapping)
	// this "params" should be fixed. They are not so you can play with different things, but in practice, the encoder has them burnt-in
	publicFixedParams := purbs.NewPublicFixedParameters(suitesInfo, simplified)

	msg := "And presently I was driving through the drizzle of the dying day, with the windshield wipers in full action but unable to cope with my tears."

	fmt.Printf("Message: %v\n", msg)
	fmt.Println(hex.Dump([]byte(msg)))
	fmt.Println()

	stream := random.New()

	// Encode (this sets-up many things, but does not output []bytes)
	recipients := createRecipients(1)
	purb, err := purbs.Encode([]byte(msg), recipients, stream, publicFixedParams, verbose)
	if err != nil {
		panic(err.Error())
	}

	// Actually map to []bytes
	blob := purb.ToBytes()

	fmt.Println("PURB created:")
	fmt.Println(hex.Dump(blob))
	fmt.Println()

	fmt.Println("PURB's internal structure:")
	fmt.Println(purb.VisualRepresentation(false))
	fmt.Println()

	// Decode
	success, decrypted, err := purbs.Decode(blob, &recipients[0], publicFixedParams, verbose)

	fmt.Println("Success:", success)
	fmt.Println("Error message:", err)
	fmt.Println(string(decrypted))
	fmt.Println(hex.Dump(decrypted))
}

func getDummySuiteInfo() purbs.SuiteInfoMap {
	info := make(purbs.SuiteInfoMap)
	cornerstoneLength := 32             // defined by Curve 25519
	entryPointLength := 16 + 4 + 4 + 16 // 16-byte symmetric key + 2 * 4-byte offset positions + 16-byte authentication tag
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &purbs.SuiteInfo{
		AllowedPositions: []int{
			12 + 0*cornerstoneLength,
			12 + 1*cornerstoneLength,
			12 + 3*cornerstoneLength,
			12 + 4*cornerstoneLength,
		},
		CornerstoneLength: cornerstoneLength, EntryPointLength: entryPointLength,
	}
	return info
}

func createRecipients(n int) []purbs.Recipient {
	decs := make([]purbs.Recipient, 0)
	suites := []purbs.Suite{curve25519.NewBlakeSHA256Curve25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := key.NewKeyPair(suite)
			decs = append(decs, purbs.Recipient{
				SuiteName:  suite.String(),
				Suite:      suite,
				PublicKey:  pair.Public,
				PrivateKey: pair.Private,
			})
		}
	}
	return decs
}
