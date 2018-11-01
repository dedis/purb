package main

import (
	"encoding/hex"
	"fmt"
	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/paper_purbs/purbs"
)

func main() {

	msg := []byte("And presently I was driving through the drizzle of the dying day, with the windshield wipers in full action but unable to cope with my tears.")

	fmt.Println(hex.Dump(msg))
	fmt.Println()

	// Encode
	si := createInfo()
	decs := createDecoders(1)
	blob, err := purbs.MakePurb(msg, decs, si, purbs.STREAM, false, random.New())
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(hex.Dump(blob))
	fmt.Println()

	// PURBDecode
	_, dec, _ := purbs.Decode(blob, &decs[0], purbs.STREAM, false, si)

	fmt.Println(hex.Dump(dec))
}

func createInfo() purbs.SuiteInfoMap {
	info := make(purbs.SuiteInfoMap)
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &purbs.SuiteInfo{
		Positions: []int{12 + 0*purbs.KEYLEN, 12 + 1*purbs.KEYLEN, 12 + 3*purbs.KEYLEN, 12 + 4*purbs.KEYLEN},
		KeyLen:    purbs.KEYLEN}
	return info
}

func createDecoders(n int) []purbs.Decoder {
	decs := make([]purbs.Decoder, 0)
	suites := []purbs.Suite{curve25519.NewBlakeSHA256Curve25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := key.NewKeyPair(suite)
			decs = append(decs, purbs.Decoder{SuiteName: suite.String(), Suite: suite, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}
