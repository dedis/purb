package purb

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
)

const (
	// Length (in bytes) of the symmetric key used to encrypt the payload
	SymmetricKeyLength = 16

	// Length (in bytes) of the pointer to the start of the payload
	StartOffsetLen = 4

	// Length (in bytes) of the pointer to the end of the payload
	EndOffsetLen = StartOffsetLen

	// Length (in bytes) of the Nonce used at the beginning of the PURB
	NonceLength = 12

	// Length (in bytes) of the MAC tag in the entry point
	// (only used with entrypoints are encrypted with AEAD)
	MacAuthenticationTagLength = 32
)

// Suite defines the required functionalities for each suite from kyber
type Suite interface {
	kyber.Encoding
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// A map of suite->info, info being the length of a marshalled public key,
// and the Allowed Positions in the purb header
type SuiteInfoMap map[string]*SuiteInfo

// SuiteInfo holds possible positions whose cornerstones might take in a header
// and a SessionKey length for this suite
type SuiteInfo struct {
	// alternative SessionKey/point position in purb header
	AllowedPositions []int
	// length of each SessionKey/point in bytes
	CornerstoneLength int
	// Length of each encrypted entry point
	EntryPointLength int
}

// Structure defining the actual header of a purb
type Header struct {
	// map of suiteName -> []entrypoints
	EntryPoints map[string][]*EntryPoint
	// Holds sender's ephemeral private/public keys for each suite in the header
	Cornerstones map[string]*Cornerstone
	// An array of byte slices where each of the bytes slice represents a hash table entry
	Layout *RegionReservationStruct
}

// Ephemeral Diffie-Hellman keys for all SessionKey-holders using this suite.
// Should have a uniform representation, e.g., an Elligator point.
type Cornerstone struct {
	SuiteName string
	KeyPair   *key.Pair
	// Starting byte position in the header
	Offset int
	// Ending byte position in the header
	EndPos int
	// Bytes: singleton. Since calling marshalling the KeyPair is non-deterministic,
	// at least we do it only once so prints are consistent
	Bytes     []byte
	SuiteInfo *SuiteInfo
}

// EntryPoint holds the info required to create an entrypoint for each recipient.
type EntryPoint struct {
	// Recipient whom this entrypoint is for
	Recipient Recipient
	// Ephemeral secret derived using DH
	SharedSecret []byte
	// Starting byte position in the header
	Offset int
	Length int
}

// Recipient holds information needed to be able to encrypt anything for it
// PrivateKey is nil for encoder
type Recipient struct {
	SuiteName string
	Suite
	PublicKey  kyber.Point
	PrivateKey kyber.Scalar
}
