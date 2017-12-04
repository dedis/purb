package purb

import "gopkg.in/dedis/crypto.v0/abstract"

type SuiteInfoMap map[string]*SuiteInfo

// SuiteInfo holds possible positions whose cornerstones might take in a header
// and a key length for this suite
type SuiteInfo struct {
	Positions []int // alternative key/point position in purb header
	KeyLen    int   // length of each key/point in bytes
}

// Ephemeral Diffie-Hellman keys for all key-holders using this suite.
// Should have a uniform representation, e.g., an Elligator point.
type Cornerstone struct {
	priv   abstract.Scalar
	pub    abstract.Point
	ellpub []byte
}

// Decoder holds information needed to be able to encrypt anything for it
type Decoder struct {
	Suite     abstract.Suite
	PublicKey abstract.Point
}

//Entry holds the info required to create an entrypoint for each recipient.
type Entry struct {
	Recipient    Decoder // Recipient whom this entrypoint is for
	Data         []byte  // Entrypoint data decryptable by recipient
	SharedSecret []byte  // Ephemeral secret derived from negotiated DH secret
	//HeaderPosition int     // Position of the entrypoint in the header of a purb
}

// Structure defining the actual header of a purb
type Header struct {
	Entries             []*Entry                // List of entrypoints
	SuitesToCornerstone map[string]*Cornerstone // Holds sender's ephemeral private/public keys for each suite in the header
	layout              [][]byte                // An array of byte slices where each of the bytes slice represents a hash table entry
	//layout      []map[int][]byte     // An array of maps where each of the maps represents a hash table and the keys are 0, 1, ... , 2^N
}

// Structure to define the whole PURB
type Purb struct {
	Header      Header
	Payload     []byte
	EncPayloads []EncPayload // A list of encrypted payloads and corresponding keys
}

type EncPayload struct {
	Key     []byte
	Suite   string
	Content []byte
	Size    int
}
