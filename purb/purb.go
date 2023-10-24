package purb

import "crypto/cipher"

// This struct's contents are *not* parameters to the PURBs. Here they vary for the simulations and the plots, but they should be fixed for all purbs
type purbConfig struct {
	suiteInfoMap                   SuiteInfoMap // public suite information (Allowed Positions, etc)
	simplifiedEntrypointsPlacement bool         // If true, does not use hash tables for entrypoints

	hashTableCollisionLinearResolutionAttempts int // Number of attempts to shift entrypoint position in a hash table by +1 if the computed position is already occupied
}

// Structure to define the whole PURB
type Purb struct {
	config *purbConfig

	nonce      []byte // Nonce used in both AEAD of entrypoints and payload. The same for different entrypoints as the keys are different. It is stored in the very beginning of the purb
	header     *Header
	payload    []byte // Payload contains already encrypted and padded plaintext
	sessionKey []byte // SessionKey is encapsulated and used to derive PayloadKey and MacKey

	recipients []Recipient   // tuple with (Suite, PublicKey, PrivateKey)
	stream     cipher.Stream // used to get randomness

	byteRepresentation []byte // the end-to-end random-looking bit array returned by ToBytes() is computed at creation time

	encryptedDataLen int    // used to record the end of encrypted data in the entry points
	originalData     []byte // kept to compare between "Payload" and this
	isVerbose        bool   // if true, the various operations on the data structure will print what is happening
}

// Creates a new PURB struct with the given parameters
func NewPurb(
	infoMap SuiteInfoMap,
	simplifiedEntryPointTable bool,
	stream cipher.Stream,
	isVerbose bool,
) *Purb {
	// Creates a struct with parameters that are *fixed* across all PURBs. Should be constants,
	// but here it is a variable for simulating various parameters
	config := &purbConfig{
		suiteInfoMap:                               infoMap,
		simplifiedEntrypointsPlacement:             simplifiedEntryPointTable,
		hashTableCollisionLinearResolutionAttempts: 3,
	}

	return &Purb{
		config:     config,
		nonce:      nil,
		header:     nil,
		payload:    nil,
		sessionKey: nil,
		stream:     stream,
		isVerbose:  isVerbose,
	}
}
