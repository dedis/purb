package purb

import (
	"fmt"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/cipher"
	"log"
	"errors"
)

// New entrypoint for a given recipient.
func NewEntry(dec Decoder, data []byte) *Entry {
	return &Entry{
		Recipient: dec,
		Data: data,
		EphemSecret: nil,
		HeaderPosition: -1,
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
			e.EphemSecret = e.Recipient.Suite.Point().Mul(e.Recipient.PublicKey, skey.dhpri)
		} else {
			return errors.New("no freshly generated private key exists for this ciphersuite")
		}
	}
	return nil
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
