package purbs

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"syscall"
	"time"

	"github.com/dedis/purb/experiments-encoding/pgp"
	"gopkg.in/dedis/kyber.v2/group/curve25519"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/kyber.v2/util/random"
)

// Fixed for the simulation: 16-byte symmetric key + 4-byte offset start position
// + 4-byte offset end position + 16-byte authentication tag
const ENTRYPOINT_LENGTH = 16 + 4 + 4 + 16

const message_size = 1024 // 1 KB
const simulationIsVerbose = false
const simulationUsesSimplifiedLayout = false

// SimulMeasureEncodingTime
func SimulMeasureEncodingTime(nRepeat int, recipients []int, suites []int) string {
	l := log.New(os.Stderr, "", 0)

	resultsPKGen := new(Results)
	resultsSharedSecrets := new(Results)
	resultsLayout := new(Results)
	resultsPayload := new(Results)
	resultsHeaderEncrypt := new(Results)
	resultsMAC := new(Results)

	m := newMonitor()
	for _, nSuites := range suites {
		for _, nRecipients := range recipients {
			for k := 0; k < nRepeat; k++ {

				msg := simulGetRandomBytes(message_size)

				l.Println("Simulating for", nRecipients, "recipients,", nSuites, "suites,", k, "/", nRepeat)

				si := createMultiInfo(nSuites)
				recipients := createMultiDecoders(nRecipients, nSuites, si)
				publicFixedParams := NewPublicFixedParameters(si, false)

				// a bit ugly, but we have to copy-paste code here (or make everything public in the PURB folder)
				purb := &Purb{
					Nonce:            nil,
					Header:           nil,
					Payload:          nil,
					SessionKey:       nil,
					Recipients:       recipients,
					Stream:           random.New(),
					OriginalData:     msg, // just for statistics
					PublicParameters: publicFixedParams,
					IsVerbose:        simulationIsVerbose,
				}
				purb.Nonce = purb.randomBytes(NONCE_LENGTH)
				purb.SessionKey = purb.randomBytes(SYMMETRIC_KEY_LENGTH)

				// creation of the entrypoints and cornerstones, places entrypoint and cornerstones
				purb.Header = newEmptyHeader()

				m.reset()
				purb.createCornerstones()
				resultsPKGen.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.recordAndReset())

				purb.createEntryPoints()
				resultsSharedSecrets.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.recordAndReset())

				purb.placeCornerstones()

				if purb.PublicParameters.SimplifiedEntrypointsPlacement {
					purb.placeEntrypointsSimplified()
				} else {
					purb.placeEntrypoints()
				}
				resultsLayout.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.recordAndReset())

				// creation of the encrypted payload
				purb.encryptThenPadData(msg, purb.Stream)

				resultsPayload.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.recordAndReset())
				// converts everything to []byte, performs the XOR trick on the cornerstones

				purb.placePayloadAndCornerstones(purb.Stream)

				resultsHeaderEncrypt.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.recordAndReset())

				// compute MAC
				purb.addMAC()
				resultsMAC.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.record())

				blob := purb.ToBytes()

				success, out, err := Decode(blob, &recipients[0], publicFixedParams, simulationIsVerbose)
				if !success || !bytes.Equal(out, msg) {
					panic("PURBs did not decrypt correctly")
				}
				if err != nil {
					panic(err.Error())
				}
			}
		}
	}

	s := "{"
	s += "\"asym-crypto\": " + resultsPKGen.String() + ","
	s += "\"shared-secrets\": " + resultsSharedSecrets.String() + ","
	s += "\"layout\": " + resultsLayout.String() + ","
	s += "\"payload\": " + resultsPayload.String() + ","
	s += "\"header-encrypt\": " + resultsHeaderEncrypt.String() + ","
	s += "\"mac\": " + resultsMAC.String()
	s += "}"

	return s
}

// SimulMeasureNumRecipients
func SimulMeasureWorstDecodingTime(nRepeat int, recipients []int, suites []int) string {
	l := log.New(os.Stderr, "", 0)

	msg := simulGetRandomBytes(message_size)

	resultsPGP := new(Results)
	resultsPGPHidden := new(Results)
	resultsPURBFlat := new(Results)
	resultsPURB := new(Results)

	m := newMonitor()
	for _, nSuites := range suites {
		for _, nRecipients := range recipients {
			for k := 0; k < nRepeat; k++ {
				l.Println("Simulating for", nRecipients, "recipients,", nSuites, "suites,", k, "/", nRepeat)
				//------------------- PGP -------------------
				recipients := make([]*pgp.PGP, 0)
				for i := 0; i < nRecipients; i++ {
					recipients = append(recipients, pgp.NewPGP())
				}
				enc, err := pgp.Encrypt(msg, recipients, false)
				if err != nil {
					log.Fatal(err)
				}

				m.reset()
				dec, err := recipients[len(recipients)-1].Decrypt(enc)
				resultsPGP.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.record())
				if err != nil {
					log.Fatal(err)
				}
				if !bytes.Equal(dec, msg) {
					panic("PGP did not decrypt correctly")
				}

				//---------------- PGP hidden -------------------
				enc, err = pgp.Encrypt(msg, recipients, true)
				if err != nil {
					log.Fatal(err)
				}
				m.reset()
				dec, err = recipients[len(recipients)-1].Decrypt(enc)
				resultsPGPHidden.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.record())
				if err != nil {
					log.Fatal(err)
				}
				if !bytes.Equal(dec, msg) {
					panic("PGP-Hidden did not decrypt correctly")
				}

				// ----------- PURBs simplified ---------------
				si := createMultiInfo(nSuites)
				decs := createMultiDecoders(nRecipients, nSuites, si)
				publicFixedParams := NewPublicFixedParameters(si, true)

				purb, err := Encode(msg, decs, random.New(), publicFixedParams, simulationIsVerbose)
				blob := purb.ToBytes()
				if err != nil {
					panic(err.Error())
				}

				m.reset()
				success, out, err := Decode(blob, &decs[len(decs)-1], publicFixedParams, simulationIsVerbose)
				resultsPURBFlat.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.record())
				if !success || !bytes.Equal(out, msg) {
					panic("PURBs-Flat did not decrypt correctly")
				}
				if err != nil {
					panic(err.Error())
				}

				// ----------------- PURBs --------------------
				si = createMultiInfo(nSuites)
				decs = createMultiDecoders(nRecipients, nSuites, si)
				publicFixedParams = NewPublicFixedParameters(si, false)

				purb, err = Encode(msg, decs, random.New(), publicFixedParams, simulationIsVerbose)
				blob = purb.ToBytes()
				if err != nil {
					panic(err.Error())
				}

				m.reset()
				success, out, err = Decode(blob, &decs[len(decs)-1], publicFixedParams, simulationIsVerbose)
				resultsPURB.add(nRecipients, nSuites, k, -1, -1, nRepeat, m.record())
				if !success || !bytes.Equal(out, msg) {
					panic("PURBs did not decrypt correctly")
				}
				if err != nil {
					panic(err.Error())
				}
			}
		}
	}

	s := "{"
	s += "\"pgp\": " + resultsPGP.String() + ","
	s += "\"pgp-hidden\": " + resultsPGPHidden.String() + ","
	s += "\"purb-flat\": " + resultsPURBFlat.String() + ","
	s += "\"purb\": " + resultsPURB.String()
	s += "}"
	return s
}

// SimulMeasureHeaderSize
func SimulMeasureHeaderSize(nRepeat int, numRecipients []int) string {
	l := log.New(os.Stderr, "", 0)

	resultsPURBs := new(Results)
	resultsFlat := new(Results)

	si := createInfo()
	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, NONCE_LENGTH)
	random.Bytes(key, random.New())
	random.Bytes(nonce, random.New())

	for _, nRecipients := range numRecipients {

		decs := createDecoders(nRecipients)
		for k := 0; k < nRepeat; k++ {
			l.Println("Simulating for", nRecipients, "recipients,", k, "/", nRepeat)
			// Baseline
			// create the PURB datastructure

			publicFixedParams := NewPublicFixedParameters(si, false)
			p := &Purb{
				Nonce:            nonce,
				Header:           nil,
				Payload:          nil,
				SessionKey:       key,
				IsVerbose:        false,
				Recipients:       decs,
				Stream:           random.New(),
				OriginalData:     nil,
				PublicParameters: publicFixedParams,
			}
			p.PublicParameters.HashTableCollisionLinearResolutionAttempts = 3
			p.CreateHeader()
			value := float64(p.Header.Length())

			resultsPURBs.add(nRecipients, -1, k, -1, -1, nRepeat, value)

			// flat
			publicFixedParams = NewPublicFixedParameters(si, true)
			p = &Purb{
				Nonce:            nonce,
				Header:           nil,
				Payload:          nil,
				SessionKey:       key,
				IsVerbose:        false,
				Recipients:       decs,
				Stream:           random.New(),
				OriginalData:     nil,
				PublicParameters: publicFixedParams,
			}
			p.CreateHeader()
			value = float64(p.Header.Length())

			resultsFlat.add(nRecipients, -1, k, -1, -1, nRepeat, value)
		}
	}

	s := "{"
	s += "\"purb\": " + resultsPURBs.String() + ","
	s += "\"purb-flat\": " + resultsFlat.String()
	s += "}"
	return s
}

// SimulMeasureHeaderCompactness
func SimulMeasureHeaderCompactness(nRepeat int, recipients []int, suites []int) string {
	l := log.New(os.Stderr, "", 0)

	resultsPURBs := new(Results)

	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, NONCE_LENGTH)
	random.Bytes(key, random.New())
	random.Bytes(nonce, random.New())

	for _, nSuites := range suites {
		for _, nRecipients := range recipients {

			for k := 0; k < nRepeat; k++ {

				si := createMultiInfoReal(nSuites)

				decs := createMultiDecoders(nRecipients, nSuites, si)
				l.Println("Simulating for", nRecipients, "recipients,", nSuites, "suites,", k, "/", nRepeat)
				// Baseline
				// create the PURB datastructure

				publicFixedParams := NewPublicFixedParameters(si, false)
				p := &Purb{
					Nonce:            nonce,
					Header:           nil,
					Payload:          nil,
					SessionKey:       key,
					IsVerbose:        false,
					Recipients:       decs,
					Stream:           random.New(),
					OriginalData:     nil,
					PublicParameters: publicFixedParams,
				}
				p.PublicParameters.HashTableCollisionLinearResolutionAttempts = 3
				p.CreateHeader()
				accu := float64(0)
				p.Header.Layout.ScanFreeRegions(func(low, high int) {
					accu += float64(high - low)
				}, p.Header.Length())

				c := accu / float64(p.Header.Length())

				resultsPURBs.add(nRecipients, nSuites, k, -1, -1, nRepeat, c)
			}
		}
	}

	return resultsPURBs.String()
}

func createInfo() SuiteInfoMap {

	entryPointLen := ENTRYPOINT_LENGTH
	cornerstoneLen := 32

	info := make(SuiteInfoMap)
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &SuiteInfo{
		AllowedPositions:  []int{12 + 0*cornerstoneLen, 12 + 1*cornerstoneLen, 12 + 3*cornerstoneLen, 12 + 4*cornerstoneLen},
		CornerstoneLength: cornerstoneLen, EntryPointLength: entryPointLen}
	return info
}

func createDecoders(n int) []Recipient {
	decs := make([]Recipient, 0)
	suites := []Suite{curve25519.NewBlakeSHA256Curve25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := key.NewKeyPair(suite)
			decs = append(decs, Recipient{SuiteName: suite.String(), Suite: suite, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}

func shiftByNONCE_LENGTH(pos []int) []int {
	res := make([]int, len(pos))

	for i := 0; i < len(pos); i++ {
		res[i] = NONCE_LENGTH + pos[i]
	}

	return res
}

func createMultiInfoReal(N int) SuiteInfoMap {

	// let's use the following suites
	// PURB_A, cornerstone size 64, ep size 48, pos 0
	// PURB_B, cornerstone size 32, ep size 48, pos 0, 64
	// PURB_C, cornerstone size 64, ep size 80, pos 0, 64, 96
	// PURB_D, cornerstone size 32, ep size 80, pos 0, 32, 64, 160
	// PURB_E, cornerstone size 64, ep size 64, pos 0, 64, 128, 192
	// PURB_F, cornerstone size 32, ep size 64, pos 0, 32, 64, 96, 128, 256

	info := make(SuiteInfoMap)

	info["PURB_A"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0}),
		CornerstoneLength: 64,
		EntryPointLength:  48,
	}
	info["PURB_B"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0, 64}),
		CornerstoneLength: 32,
		EntryPointLength:  48,
	}
	info["PURB_C"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0, 64, 96}),
		CornerstoneLength: 64,
		EntryPointLength:  80,
	}
	info["PURB_D"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0, 32, 64, 160}),
		CornerstoneLength: 32,
		EntryPointLength:  80,
	}
	info["PURB_E"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0, 64, 128, 192}),
		CornerstoneLength: 64,
		EntryPointLength:  64,
	}
	info["PURB_F"] = &SuiteInfo{
		AllowedPositions:  shiftByNONCE_LENGTH([]int{0, 32, 64, 96, 128, 256}),
		CornerstoneLength: 32,
		EntryPointLength:  64,
	}

	keys := make([]string, 0)
	for k := range info {
		keys = append(keys, k)
	}
	rand.Seed(time.Now().UTC().UnixNano())
	for len(info) > N {
		to_destroy := keys[rand.Intn(len(keys))]
		delete(info, to_destroy)
	}

	return info
}

func createMultiInfo(N int) SuiteInfoMap {

	entryPointLen := ENTRYPOINT_LENGTH
	cornerstoneLen := 32
	aeadNonceLen := 12

	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := aeadNonceLen
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*cornerstoneLen
			floor += int(math.Pow(2, float64(i))) * cornerstoneLen
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			AllowedPositions: positions[i], CornerstoneLength: cornerstoneLen, EntryPointLength: entryPointLen}
	}

	return info
}

func createMultiDecoders(n int, numberOfSuites int, si SuiteInfoMap) []Recipient {
	type suite struct {
		Name  string
		Value Suite
	}
	decs := make([]Recipient, 0)
	suites := make([]suite, 0)
	for name := range si {
		if len(suites) >= numberOfSuites {
			break
		}
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for n > 0 {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, Recipient{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Private})
			n--
			if n == 0 {
				break
			}
		}
	}
	return decs
}

// Helpers for measurement of CPU cost of operations
type Monitor struct {
	CPUtime float64
}

func newMonitor() *Monitor {
	var m Monitor
	m.CPUtime = getCPUTime()
	return &m
}

func (m *Monitor) reset() {
	m.CPUtime = getCPUTime()
}

func (m *Monitor) record() float64 {
	return getCPUTime() - m.CPUtime
}

func (m *Monitor) recordAndReset() float64 {
	old := m.CPUtime
	m.CPUtime = getCPUTime()
	return m.CPUtime - old
}

// Returns the sum of the system and the user CPU time used by the current process so far.
func getCPUTime() float64 {
	rusage := &syscall.Rusage{}
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, rusage); err != nil {
		log.Fatalln("Couldn't get rusage time:", err)
		return -1
	}
	s, u := rusage.Stime, rusage.Utime // system and user time
	return iiToF(int64(s.Sec), int64(s.Usec)) + iiToF(int64(u.Sec), int64(u.Usec))
}

// Converts to milliseconds
func iiToF(sec int64, usec int64) float64 {
	return float64(sec)*1000.0 + float64(usec)/1000.0
}

func simulGetRandomBytes(length int) []byte {
	buffer := make([]byte, length)
	random.Bytes(buffer, random.New())
	return buffer
}

// ResultRow contains data about one sample of one experiment
type ResultRow struct {
	nRecipients      int
	totalNRecipients int

	nSuites      int
	totalNSuites int

	nRepeat      int
	totalNRepeat int

	value float64
}

// Results is a collection of ResultRow's
type Results struct {
	rows []*ResultRow
}

func (results *Results) add(nRecipients, nSuites, nRepeat, totalNRecipients, totalNSuites, totalNRepeat int, value float64) {

	if results.rows == nil {
		results.rows = make([]*ResultRow, 0)
	}

	r := new(ResultRow)
	r.nRecipients = nRecipients
	r.totalNRecipients = totalNRecipients
	r.nSuites = nSuites
	r.totalNSuites = totalNSuites
	r.nRepeat = nRepeat
	r.totalNRepeat = totalNRepeat
	r.value = value

	results.rows = append(results.rows, r)
}

func (results Results) String() string {
	s := "["
	for _, r := range results.rows {
		s += r.String()
	}
	s = s[0:len(s)-1] + "]"
	return s
}

func (r ResultRow) String() string {
	return fmt.Sprintf("{\"nRecipients\": \"%d\", \"nSuites\": \"%d\", \"nRepeat\": \"%d\", \"totalNRecipients\": \"%d\", \"totalNSuites\": \"%d\", \"totalNRepeat\": \"%d\", \"value\": \"%f\"},", r.nRecipients, r.nSuites, r.nRepeat, r.totalNRecipients, r.totalNSuites, r.totalNRepeat, r.value)
}
