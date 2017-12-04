package purb

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/nist"
	"fmt"
	"gopkg.in/dedis/crypto.v0/edwards"
	"gopkg.in/dedis/crypto.v0/random"
	"encoding/hex"
)

func TestPurb(t *testing.T) {
	//info := createInfo()
	//fmt.Println(info[edwards.NewAES128SHA256Ed25519(false).String()].Positions)
	//h := NewEmptyHeader()
	//h.Fill()
}

func TestPurb_EncryptPayload(t *testing.T) {
	payload := []byte("Test AEAD")
	p := NewPurb(payload)
	p.Header.SuitesToCornerstone[edwards.NewAES128SHA256Ed25519(false).String()] = &Cornerstone{}
	p.Header.SuitesToCornerstone[nist.NewAES128SHA256P256().String()] = &Cornerstone{}
	p.EncryptPayload(random.Stream)
	fmt.Println("Text length: ", len(payload))
	fmt.Printf("Suite: %s \n Key: %s \n Content: %s \n Size: %d \n", p.EncPayloads[0].Suite,
		hex.EncodeToString(p.EncPayloads[0].Key), hex.EncodeToString(p.EncPayloads[0].Content), p.EncPayloads[0].Size)
}

func createInfo() SuiteInfoMap {
	info := make(SuiteInfoMap)
	info[edwards.NewAES128SHA256Ed25519(false).String()] = &SuiteInfo{
		Positions: []int{0, 32, 96},
		KeyLen:    KEYLEN,}
	info[nist.NewAES128SHA256P256().String()] = &SuiteInfo{
		Positions: []int{0, 32, 128},
		KeyLen:    KEYLEN,}
	return info
}
