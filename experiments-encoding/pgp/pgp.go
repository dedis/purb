package pgp

import (
	"bytes"
	"time"

	"errors"

	"crypto"
	"crypto/rand"

	"crypto/elliptic"
	"github.com/nikirill/go-crypto/curve25519"
	"github.com/nikirill/go-crypto/openpgp"
	"github.com/nikirill/go-crypto/openpgp/armor"
	"github.com/nikirill/go-crypto/openpgp/ecdh"
	"github.com/nikirill/go-crypto/openpgp/packet"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
)

/*
* PGP - wrappers
 */

type PGP struct {
	Public  *packet.PublicKey
	Private *packet.PrivateKey
}

func NewPGP() *PGP {
	//suite := curve25519.NewBlakeSHA256Curve25519()
	secret, _ := gen25519KeyPair()
	priv := packet.NewECDHPrivateKey(time.Now(), secret)
	public := packet.PublicKey(priv.PublicKey)
	return &PGP{
		Private: priv,
		Public:  &public,
	}
}

func gen25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey) {
	// Generate private and public keys for curve255519
	var priv []byte
	var x, y *big.Int
	var err error
	priv, x, y, err = elliptic.GenerateKey(curve25519.Cv25519(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	ecdhpriv := new(ecdh.PrivateKey)
	ecdhpriv.X = new(big.Int).SetBytes(priv)

	ecdhpub := new(ecdh.PublicKey)
	ecdhpub.Curve = curve25519.Cv25519()
	ecdhpub.X = x
	ecdhpub.Y = y
	ecdhpriv.PublicKey = *ecdhpub

	return ecdhpriv, ecdhpub
}

func Encrypt(plaintext []byte, recipients []*PGP, hidden bool) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients given")
	}
	out := &bytes.Buffer{}
	entities := make([]*openpgp.Entity, 0)
	for _, r := range recipients {
		entities = append(entities, r.Entity())
	}
	in, err := openpgp.Encrypt(out, entities, nil, nil, &packet.Config{Hidden: hidden})
	if err != nil {
		return nil, err
	}
	in.Write(plaintext)
	in.Close()
	return out.Bytes(), nil
}

func (p *PGP) Decrypt(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	kr := openpgp.EntityList{p.Entity()}
	msgd, err := openpgp.ReadMessage(r, kr, nil, nil)
	if err != nil {
		return nil, err
	}
	out := &bytes.Buffer{}
	out.ReadFrom(msgd.UnverifiedBody)
	//fmt.Printf("Message for keyIDs %x\n", msgd.EncryptedToKeyIds)
	return out.Bytes(), nil
}

func (p *PGP) Sign(data []byte) (string, error) {
	if p.Private == nil {
		return "", errors.New("no private key defined")
	}
	in := bytes.NewBuffer(data)
	out := &bytes.Buffer{}
	err := openpgp.ArmoredDetachSign(out, p.Entity(), in, nil)

	return out.String(), err
}

func (p *PGP) Verify(data []byte, sigStr string) error {
	// open ascii armored public key
	in := bytes.NewBufferString(sigStr)

	block, err := armor.Decode(in)
	log.ErrFatal(err)

	if block.Type != openpgp.SignatureType {
		log.Fatal("Invalid signature file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	log.ErrFatal(err)

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Fatal("Invalid signature")
	}

	hash := sig.Hash.New()
	hash.Write(data)

	return p.Public.VerifySignature(hash, sig)
}

func ArmorEncryption(enc []byte) string {
	arm := &bytes.Buffer{}
	wArm, err := armor.Encode(arm, "Message", make(map[string]string))
	log.ErrFatal(err)
	wArm.Write(enc)
	log.ErrFatal(wArm.Close())
	return arm.String()
}

func (p *PGP) ArmorPrivate() string {
	priv := &bytes.Buffer{}
	wPriv, err := armor.Encode(priv, openpgp.PrivateKeyType, make(map[string]string))
	log.ErrFatal(err)
	log.ErrFatal(p.Private.Serialize(wPriv))
	log.ErrFatal(wPriv.Close())
	return priv.String()
}

func (p *PGP) ArmorPublic() string {
	pub := &bytes.Buffer{}
	wPub, err := armor.Encode(pub, openpgp.PublicKeyType, make(map[string]string))
	log.ErrFatal(err)

	log.ErrFatal(p.Public.Serialize(wPub))
	log.ErrFatal(wPub.Close())
	return pub.String()
}

func (p *PGP) Entity() *openpgp.Entity {
	config := packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES128,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: p.Public,
		PrivateKey: p.Private,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime:       currentTime,
			SigType:            packet.SigTypePositiveCert,
			PubKeyAlgo:         packet.PubKeyAlgoECDH,
			Hash:               crypto.SHA256,
			PreferredHash:      []uint8{8},
			PreferredSymmetric: []uint8{7},
			IsPrimaryId:        &isPrimaryId,
			FlagsValid:         true,
			FlagSign:           true,
			FlagCertify:        true,
			IssuerKeyId:        &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  p.Public,
		PrivateKey: p.Private,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoECDSA,
			Hash:                      crypto.SHA256,
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func DecodePrivate(priv string) *packet.PrivateKey {
	// open ascii armored private key
	in := bytes.NewBufferString(priv)
	block, err := armor.Decode(in)
	log.ErrFatal(err)

	if block.Type != openpgp.PrivateKeyType {
		log.Fatal("Invalid private key file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	log.ErrFatal(err)

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Fatal("Invalid private key")
	}
	return key
}

func DecodePublic(pub string) *packet.PublicKey {
	in := bytes.NewBufferString(pub)
	block, err := armor.Decode(in)
	log.ErrFatal(err)

	if block.Type != openpgp.PublicKeyType {
		log.Fatal("Invalid private key file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	log.ErrFatal(err)

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Fatal("Invalid public key")
	}
	return key
}
