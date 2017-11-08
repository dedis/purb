package purb

import "gopkg.in/dedis/crypto.v0/abstract"

//Length each entrypoint is (for simplicity assuming all suites HideLen is the same).
const KEYLEN = 32

//Change this value to see if it can give nicer numbers
//--Trade off between header size and decryption time.
const HASHATTEMPTS = 5

//How many bytes symkey+message_start is
const DATALEN = 24

// Maximum number of supported cipher suites
const MAXSUITS = 3

type SuiteToInfo map[string]*SuiteInfo

// SuiteInfo holds possible positions whose cornerstones might take in a header
// and a key length for this suite
type SuiteInfo struct {
	Positions []int // alternative key/point position in purb header
	KeyLen    int   // length of each key/point in bytes
}

// Ephemeral Diffie-Hellman keys for all key-holders using this suite.
// Should have a uniform representation, e.g., an Elligator point.
type suiteKey struct {
	dhpri abstract.Scalar
	dhpub abstract.Point
	dhrep []byte
}

// Decoder holds information needed to be able to encrypt anything for it
type Decoder struct {
	Suite     abstract.Suite
	PublicKey abstract.Point
}

//Entry holds the info required to create an entrypoint for each recipient.
type Entry struct {
	Recipient      Decoder        // Recipient whom this entrypoint is for
	Data           []byte         // Entrypoint data decryptable by recipient
	EphemSecret    abstract.Point // Ephemeral secret used to encrypt the entry point
	HeaderPosition int            // Position of the entrypoint in the header of a purb
}

// Structure defining the actual header of a purb
type Header struct {
	Entries     []*Entry                    // List of entrypoints
	SuiteToKeys map[string]*suiteKey // Holds ephemeral keys for each suite in the header
	buf         []byte                      // Buffer in which to build message
}
