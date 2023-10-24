package purb

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
)

// Length (in bytes) of the symmetric key used to encrypt the payload
const SYMMETRIC_KEY_LENGTH = 16

// Length (in bytes) of the pointer to the start of the payload
const START_OFFSET_LEN = 4

// Length (in bytes) of the pointer to the end of the payload
const END_OFFSET_LEN = START_OFFSET_LEN

// Length (in bytes) of the Nonce used at the beginning of the PURB
const NONCE_LENGTH = 12

// Length (in bytes) of the MAC tag in the entry point (only used with entrypoints are encrypted with AEAD)
const MAC_AUTHENTICATION_TAG_LENGTH = 32

// Suite defines the required functionalities for each suite from kyber
type Suite interface {
	kyber.Encoding
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// A map of suite->info, info being the length of a marshalled public key, and the Allowed Positions in the purb header
type SuiteInfoMap map[string]*SuiteInfo

// SuiteInfo holds possible positions whose cornerstones might take in a header
// and a SessionKey length for this suite
type SuiteInfo struct {
	AllowedPositions  []int // alternative SessionKey/point position in purb header
	CornerstoneLength int   // length of each SessionKey/point in bytes
	EntryPointLength  int   // Length of each encrypted entry point
}

// Structure defining the actual header of a purb
type Header struct {
	EntryPoints  map[string][]*EntryPoint // map of suiteName -> []entrypoints
	Cornerstones map[string]*Cornerstone  // Holds sender's ephemeral private/public keys for each suite in the header
	Layout       *RegionReservationStruct // An array of byte slices where each of the bytes slice represents a hash table entry
}

// Ephemeral Diffie-Hellman keys for all SessionKey-holders using this suite.
// Should have a uniform representation, e.g., an Elligator point.
type Cornerstone struct {
	SuiteName string
	KeyPair   *key.Pair
	Offset    int    // Starting byte position in the header
	EndPos    int    // Ending byte position in the header
	Bytes     []byte // singleton. Since calling marshalling the KeyPair is non-deterministic, at least we do it only once so prints are consistents
	SuiteInfo *SuiteInfo
}

// EntryPoint holds the info required to create an entrypoint for each recipient.
type EntryPoint struct {
	Recipient    Recipient // Recipient whom this entrypoint is for
	SharedSecret []byte    // Ephemeral secret derived using DH
	Offset       int       // Starting byte position in the header
	Length       int
}

// Recipient holds information needed to be able to encrypt anything for it
// PrivateKey is nil for encoder
type Recipient struct {
	SuiteName string
	Suite
	PublicKey  kyber.Point
	PrivateKey kyber.Scalar
}
