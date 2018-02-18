package simul

import (
	"bytes"
	"time"

	"errors"

	"crypto/elliptic"
	"crypto/rand"

	"gopkg.in/dedis/onet.v1/log"

	"github.com/benburkert/openpgp/ecdh"
	"github.com/benburkert/openpgp/packet"
	"github.com/benburkert/openpgp"
	"github.com/benburkert/openpgp/armor"
	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/encoding"
)

/*
* PGP - wrappers
 */

type PGP struct {
	Public  *packet.PublicKey
	Private *packet.PrivateKey
}

func NewPGP() *PGP {
	key, err := ecdh.GenerateKey(elliptic.P256(), rand.Reader)
	key.KDF = encoding.NewBitString([]byte{0x00, algorithm.SHA256.Id(), algorithm.AES256.Id()})
	log.ErrFatal(err)
	return &PGP{
		Public:  packet.NewECDHPublicKey(time.Now(), &key.PublicKey),
		Private: packet.NewECDHPrivateKey(time.Now(), key),
	}
}

//func NewPGPPublic(public string) *PGP {
//	return &PGP{Public: DecodePublic(public)}
//}
//
//func NewECDHPublic(public *packet.PublicKey) *PGP {
//	return &PGP{Public: public}
//}

func (p *PGP) Encrypt(plaintext []byte, recipients []*PGP) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients given")
	}
	out := &bytes.Buffer{}
	entities := make([]*openpgp.Entity, 0)
	for _, r := range recipients {
		entities = append(entities, r.Entity())
	}
	in, err := openpgp.Encrypt(out, entities, nil, nil, nil)
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


func (p *PGP) ArmorEncryption(enc []byte) string {
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
		DefaultHash:   algorithm.SHA256,
		DefaultCipher: algorithm.AES256,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: p.Public,
		PrivateKey: p.Private,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	cslice := make(algorithm.CipherSlice, 1)
	cslice[0] = algorithm.AES256
	hslice := make(algorithm.HashSlice, 1)
	hslice[0] = algorithm.SHA256

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime:       currentTime,
			SigType:            packet.SigTypePositiveCert,
			PubKeyAlgo:         algorithm.ECDH,
			Hash:               algorithm.SHA256,
			PreferredSymmetric: cslice,
			PreferredHash:      hslice,
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
			PubKeyAlgo:                algorithm.ECDSA,
			Hash:                      algorithm.SHA256,
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
