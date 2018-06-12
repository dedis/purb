package pgp

import (
	"testing"

	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v1/log"
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
	recipients := make([]*PGP, 0)
	for i := 0; i < 100; i++ {
		recipients = append(recipients, NewPGP())
	}
	// Normal PGP
	fmt.Println("=================TEST Normal PGP=================")
	enc, err := Encrypt(msg, recipients, false)
	if err != nil {
		log.ErrFatal(err)
	}
	//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
	dec, err := recipients[len(recipients)-1].Decrypt(enc)
	if err != nil {
		log.Fatal(err)
	}
	require.Equal(t, msg, dec)

	// Hidden recipients
	fmt.Println("==========TEST PGP with Hidden Recipients========")
	enc, err = Encrypt(msg, recipients, true)
	if err != nil {
		log.ErrFatal(err)
	}
	//fmt.Printf("Encryption:\n%s\n", ArmorEncryption(enc))
	dec, err = recipients[len(recipients)-1].Decrypt(enc)
	if err != nil {
		log.Fatal(err)
	}
	require.Equal(t, msg, dec)
}
