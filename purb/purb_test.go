package purb

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/edwards"
)

func TestPurb(t *testing.T) {
	var info SuiteToInfo
	info[edwards.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
		Positions: []int{0, 32, 96},
		KeyLen: KEYLEN}
}

func TestHeader_GenSuiteKeys(t *testing.T) {

}