package purb

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
)

// Suite defines the required functionalities for each suite from kyber
type Suite interface {
	kyber.Encoding
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

type SuiteInfoMap map[string]*SuiteInfo // suite info indexed by suite names

// SuiteInfo holds possible positions whose cornerstones might take in a header
// and a key length for this suite
type SuiteInfo struct {
	Positions []int // alternative key/point position in purb header
	KeyLen    int   // length of each key/point in bytes
}

// Structure to define the whole PURB
type Purb struct {
	Nonce []byte // Nonce used in both AEAD of entrypoints and payload. The same for different entrypoints
	// as the keys are different. It is stored in the very beginning of the purb
	Header  *Header
	Payload []byte // Payload contains already padded plaintext
	key     []byte // Payload key
	buf     []byte // Buffer to store intermediate binary representation of purb
}

// Structure defining the actual header of a purb
type Header struct {
	SuitesToEntries     map[string][]*Entry     // List of entrypoints
	SuitesToCornerstone map[string]*Cornerstone // Holds sender's ephemeral private/public keys for each suite in the header
	Layout              SkipLayout              // An array of byte slices where each of the bytes slice represents a hash table entry
	Length              int                     //
	EntryLen            int                     // Length of each encrypted entry point
}

// Ephemeral Diffie-Hellman keys for all key-holders using this suite.
// Should have a uniform representation, e.g., an Elligator point.
type Cornerstone struct {
	SuiteName string
	KeyPair   *key.Pair
	Offset    int // Starting byte position in the header
}

//Entry holds the info required to create an entrypoint for each recipient.
type Entry struct {
	Recipient    Decoder // Recipient whom this entrypoint is for
	SharedSecret []byte  // Ephemeral secret derived from negotiated DH secret
	Offset       int     // Starting byte position in the header
}

// Decoder holds information needed to be able to encrypt anything for it
// PrivateKey is nil for encoder
type Decoder struct {
	SuiteName  string
	Suite
	PublicKey  kyber.Point
	PrivateKey kyber.Scalar
}
