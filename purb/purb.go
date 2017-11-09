package purb

import (
	"fmt"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/cipher"
	"log"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
)

// New entrypoint for a given recipient.
func NewEntry(dec Decoder, data []byte) *Entry {
	return &Entry{
		Recipient:      dec,
		Data:           data,
		EphemSecret:    nil,
		HeaderPosition: -1,
	}
}

// New empty Header with initialized maps.
func NewHeader() *Header {
	b := make([]byte, 0)
	s2k := make(map[string]*suiteKey)
	return &Header{
		Entries:     nil,
		SuiteToKeys: s2k,
		buf:         b,
	}
}

// Find what unique suits Decoders of the message use,
// generate a private for each of these suites, and assign
// them to corresponding entry points
func (h *Header) GenSuiteKeys(rand cipher.Stream) error {
	for _, e := range h.Entries {
		var priv abstract.Scalar
		var pub abstract.Point
		var rep []byte
		if _, ok := h.SuiteToKeys[e.Recipient.Suite.String()]; !ok {
			for correct := false; correct != true; {
				// Generate a fresh private key (scalar) and compute a public key (point)
				priv = e.Recipient.Suite.NewKey(rand)
				pub = e.Recipient.Suite.Point().Mul(nil, priv)
				rep = pub.(abstract.Hiding).HideEncode(rand)
				if priv != nil && pub != nil {
					if rep != nil {
						correct = true
					}
				} else {
					return errors.New("generated private or public keys were nil")
				}
			}
			h.SuiteToKeys[e.Recipient.Suite.String()] = &suiteKey{dhpri: priv, dhpub: pub, dhrep: rep,}
		}
	}
	return nil
}

// Compute an ephemeral secret per entrypoint used ot encrypt it.
// It takes a public key of a recipient and multiplies it by fresh
// private key for a given cipher suite.
func (h *Header) ComputeEphemSecrets(rand cipher.Stream) error {
	for _, e := range h.Entries {
		skey, ok := h.SuiteToKeys[e.Recipient.Suite.String()]
		if ok {
			sharedKey := e.Recipient.Suite.Point().Mul(e.Recipient.PublicKey, skey.dhpri) // Compute shared DH key
			if sharedKey != nil {
				sharedBytes, _ := sharedKey.MarshalBinary()
				e.EphemSecret = KDF(sharedBytes) // Derive a key using KDF
			} else {
				return errors.New("couldn't negotiate a shared DH key")
			}
		} else {
			return errors.New("no freshly generated private key exists for this ciphersuite")
		}
	}
	return nil
}

func KDF(password []byte) []byte {
	return pbkdf2.Key(password, nil, 1, 32, sha256.New)
}

func (e *Entry) String() string {
	return fmt.Sprintf("(%s)%p", e.Recipient.Suite, e)
}

// Sets the position of each entry point in a purb
func (h *Header) Make() {

}

// Finalize and encrypt the negotiation message.
// The data slices in all the entrypoints must be filled in
// before calling this function.
func (h *Header) Write(rand cipher.Stream) []byte {
	return nil
}

func (h *Header) growBuffer(high int) {
	if len(h.buf) < high {
		b := make([]byte, high)
		copy(b, h.buf)
		h.buf = b
	} else {
		log.Println("Header buffer is already large enough")
	}
}
