package purb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"go.dedis.ch/kyber/v3/group/curve25519"
	"go.dedis.ch/kyber/v3/util/random"
)

// Simply returns a string with the internal details of the PURB
func (p *Purb) VisualRepresentation(withBoundaries bool) string {

	lines := make([]string, 0)

	bytes := p.ToBytes()

	lines = append(lines, "*** PURB Details ***")
	lines = append(lines, fmt.Sprintf("Original Data: len %v", len(p.originalData)))
	lines = append(lines,
		fmt.Sprintf("PURB: header at 0 (len %v), payload at %v (len %v), total %v bytes",
			p.header.Length(), p.header.Length(), len(p.payload), len(bytes)))

	lines = append(lines, fmt.Sprintf("Nonce: %+v (len %v)", p.nonce, len(p.nonce)))

	for _, cornerstone := range p.header.Cornerstones {
		lines = append(lines,
			fmt.Sprintf("Cornerstones: %+v @ offset %v (len %v)", cornerstone.SuiteName,
				cornerstone.Offset,
				p.config.suiteInfoMap[cornerstone.SuiteName].CornerstoneLength))

		lines = append(lines, fmt.Sprintf("  Value: %v", cornerstone.Bytes))
		lines = append(lines, fmt.Sprintf("  Allowed positions for this suite: %v",
			p.config.suiteInfoMap[cornerstone.SuiteName].AllowedPositions))

		cornerstoneStartPosUsed := make([]int, 0)
		for _, startPos := range p.config.suiteInfoMap[cornerstone.SuiteName].AllowedPositions {
			if startPos < len(bytes) {
				cornerstoneStartPosUsed = append(cornerstoneStartPosUsed, startPos)
			}
		}

		cornerstoneRangesUsed := make([]string, 0)
		cornerstoneRangesValues := make([][]byte, 0)
		for _, startPos := range cornerstoneStartPosUsed {
			endPos := startPos + p.config.suiteInfoMap[cornerstone.SuiteName].CornerstoneLength
			if endPos > len(bytes) {
				endPos = len(bytes)
			}
			cornerstoneRangesUsed = append(cornerstoneRangesUsed,
				strconv.Itoa(startPos)+":"+strconv.Itoa(endPos))
			cornerstoneRangesValues = append(cornerstoneRangesValues, bytes[startPos:endPos])
		}
		lines = append(lines, fmt.Sprintf("  Positions used: %v", cornerstoneRangesUsed))

		xor := make([]byte, len(cornerstoneRangesValues[0]))
		// XORed, those values should give back the cornerstone value
		for i := range cornerstoneRangesValues {
			lines = append(lines, fmt.Sprintf("  Value @ pos[%v]: %v", cornerstoneRangesUsed[i],
				cornerstoneRangesValues[i]))

			for i, b := range cornerstoneRangesValues[i] {
				xor[i] ^= b
			}
		}

		lines = append(lines, fmt.Sprintf("  Recomputed value: %v", xor))

	}
	for suiteName, entrypoints := range p.header.EntryPoints {
		lines = append(lines, fmt.Sprintf("Entrypoints for suite %v", suiteName))
		for index, entrypoint := range entrypoints {
			lines = append(lines, fmt.Sprintf("  Entrypoints [%v]: %+v @ offset %v (len %v)", index,
				entrypoint.SharedSecret, entrypoint.Offset, entrypoint.Length))
		}
	}
	lines = append(lines,
		fmt.Sprintf("Padded Payload: %+v @ offset %v (len %v)", p.payload, p.header.Length(),
			len(p.payload)))

	lines = append(lines,
		fmt.Sprintf("MAC: %+v @ offset %v (len %v)", getMAC(p.byteRepresentation),
			len(p.byteRepresentation)-MacAuthenticationTagLength,
			MacAuthenticationTagLength))

	if !withBoundaries {
		return strings.Join(lines, "\n")
	}

	// just cosmetics
	max := 0
	for _, line := range lines {
		if len(line) > max {
			max = len(line)
		}
	}

	for i := range lines {
		lines[i] = "| " + lines[i] + strings.Repeat(" ", max-len(lines[i])) + " |"
	}

	top := strings.Repeat("_", max+4) + "\n"
	body := strings.Join(lines, "\n") + " \n"
	bottom := strings.Repeat("-", max+4) + "\n"

	return "\n" + top + body + bottom
}

// Encrypt using AEAD
func aeadEncrypt(data, nonce, key, additional []byte, stream cipher.Stream) ([]byte, error) {

	// If no key is passed, generate a random 16-byte key and create a cipher from it
	if key == nil {
		key := make([]byte, SymmetricKeyLength)
		random.Bytes(key, stream)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt and authenticate payload
	encrypted := aesgcm.Seal(nil, nonce, data, additional)

	return encrypted, nil
}

// Decrypt using AEAD
func aeadDecrypt(ciphertext, nonce, key, additional []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify payload
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, additional)

	return decrypted, err
}

// Encrypt using a stream cipher Blake2xb where key is used as the seed
func streamEncrypt(data, key []byte) []byte {
	ciphertext := make([]byte, len(data))
	suite := curve25519.NewBlakeSHA256Curve25519(true)
	xof := suite.XOF(key)
	xof.XORKeyStream(ciphertext, data)

	return ciphertext
}

// Encrypt using a stream cipher Blake2xb
func streamDecrypt(ciphertext, key []byte) []byte {
	data := make([]byte, len(ciphertext))
	suite := curve25519.NewBlakeSHA256Curve25519(true)
	xof := suite.XOF(key)
	xof.XORKeyStream(data, ciphertext)

	return data
}

// KDF derives a key from a purpose string and seed bytes
func KDF(purpose string, seed []byte) []byte {
	h := sha256.New()
	h.Write([]byte(purpose))
	h.Write(seed)
	return h.Sum(nil)
	//return pbkdf2.Key(password, nil, 1, 32, sha256.New)
}

func (si SuiteInfo) String() string {
	s := "[positions: {"

	for _, pos := range si.AllowedPositions {
		s += strconv.Itoa(pos) + ", "
	}
	s = s[0:len(s)-2] + "}, "
	s += "CSLen: " + strconv.Itoa(si.CornerstoneLength)
	s += ", EPLen: " + strconv.Itoa(si.EntryPointLength)

	return s + "]"
}
