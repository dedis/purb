package simul

import (
	"testing"

	"gopkg.in/dedis/onet.v1/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"fmt"
)

func TestNewPGP(t *testing.T) {
	pgp := NewPGP()
	assert.NotNil(t, pgp)
	pgp2 := NewPGP()
	assert.NotEqual(t, pgp.ArmorPrivate(), pgp2.ArmorPrivate())
	assert.NotEqual(t, pgp.ArmorPublic(), pgp2.ArmorPublic())
}

func TestPGP_EncryptDecrypt(t *testing.T) {
	msg := []byte("gorilla")
	sender := NewPGP()
	recipients := make([]*PGP, 0)
	for i:=0; i<100; i++ {
		recipients = append(recipients, NewPGP())
	}
	//pgp2 := NewECDHPublic(pgp.Public)
	enc, err := sender.Encrypt(msg, recipients)
	if err != nil {
		log.ErrFatal(err)
	}
	fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
	dec, err := recipients[len(recipients)-1].Decrypt(enc)
	if err != nil {
		log.Fatal(err)
	}
	require.Equal(t, msg, dec)
	//fmt.Printf("Decrypted:\n%s\n", dec)
}