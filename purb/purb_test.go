package purb

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/nist"
	"fmt"
	"gopkg.in/dedis/crypto.v0/edwards"
)

func TestPurb(t *testing.T) {
	info := createInfo()
	fmt.Println(info[edwards.NewAES128SHA256Ed25519(false).String()].Positions)
}

//func TestHeader_GenSuiteKeys(t *testing.T) {
//
//}

func createInfo() SuiteToInfo {
	info := make(SuiteToInfo)
	info[edwards.NewAES128SHA256Ed25519(false).String()] = &SuiteInfo{
		Positions: []int{0, 32, 96},
		KeyLen:    KEYLEN,}
	info[nist.NewAES128SHA256P256().String()] = &SuiteInfo{
		Positions: []int{0, 32, 128},
		KeyLen:    KEYLEN,}
	return info
}
