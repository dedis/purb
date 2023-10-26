package purb

import "crypto/cipher"

// This struct's contents are *not* parameters to the PURBs.
// Here they vary for the simulations and the plots, but they should be fixed for all purbs
type purbConfig struct {
	// public suite information (Allowed Positions, etc)
	suiteInfoMap SuiteInfoMap

	// If true, does not use hash tables for entrypoints
	simplifiedEntrypointsPlacement bool

	// Number of attempts to shift entrypoint position in a hash table by +1
	// if the computed position is already occupied
	hashTableCollisionLinearResolutionAttempts int
}

// Structure to define the whole PURB
type Purb struct {
	config *purbConfig

	// nonce used in both AEAD of entrypoints and payload.
	// The same for different entrypoints as the keys are different.
	// It is stored in the very beginning of the purb
	nonce  []byte
	header *Header

	// payload contains already encrypted and padded plaintext
	payload []byte

	// sessionKey is encapsulated and used to derive PayloadKey and MacKey
	sessionKey []byte

	// tuple with (Suite, PublicKey, PrivateKey)
	Recipients []Recipient

	// used to get randomness
	stream cipher.Stream

	// the end-to-end random-looking bit array returned by ToBytes() is computed at creation time
	byteRepresentation []byte

	// used to record the end of encrypted data in the entry points
	encryptedDataLen int

	// kept to compare between payload and originalData
	originalData []byte
}

// Creates a new PURB struct with the given parameters
func NewPurb(
	infoMap SuiteInfoMap,
	simplifiedEntryPointTable bool,
	stream cipher.Stream,
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
	}
}
