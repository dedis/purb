package simul

import (
	"testing"

	"gopkg.in/dedis/onet.v1/log"
	"github.com/stretchr/testify/assert"
	"fmt"
)

func TestNewPGP(t *testing.T) {
	pgp := NewPGP()
	assert.NotNil(t, pgp)
	pgp2 := NewPGP()
	assert.NotEqual(t, pgp.ArmorPrivate(), pgp2.ArmorPrivate())
	assert.NotEqual(t, pgp.ArmorPublic(), pgp2.ArmorPublic())
}

func TestPGP_Encrypt(t *testing.T) {
	msg := []byte("gorilla")
	pgp := NewPGP()
	//pgp2 := NewECDHPublic(pgp.Public)
	pgp2 := pgp
	recipients := make([]*PGP, 1)
	recipients[0] = pgp2
	result, err := pgp.Encrypt(msg, recipients)
	if err != nil {
		log.ErrFatal(err)
	}
	fmt.Printf("Result is %x", result)

}