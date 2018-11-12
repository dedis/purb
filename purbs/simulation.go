package purbs

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"syscall"

	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/purbs/experiments-encoding/pgp"
)

const simulationIsVerbose = false
const simulationUsesSimplifiedLayout = false

// SimulMeasureNumRecipients
func SimulMeasureNumRecipients() {
	msg := simulGetRandomBytes(100)

	log.Printf("Length of the message is %d bytes\n", len(msg))
	nums := []int{1, 3, 5, 10, 30, 70, 100, 1000, 3000, 10000}
	//nums := []int{1, 3, 5, 10, 30, 70, 100}
	//nums := []int{1000, 3000, 10000}
	// File to write results to
	f, err := os.Create("simul_num_recipients_ex.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(strings.Trim(fmt.Sprint(nums), "[]") + "\n")
	for _, N := range nums {
		var tPGPclear, tPGPhidden, tPURBs, tPURBhash []float64
		si := createMultiInfo(1)
		decs := createDecoders(N)
		f.WriteString(fmt.Sprint(N) + "\n")
		log.Println(N)
		for k := 0; k < 21; k++ {
			log.Println("Iteration ", k)
			//------------------- PGP -------------------
			//sender := NewPGP()
			recipients := make([]*pgp.PGP, 0)
			for i := 0; i < N; i++ {
				recipients = append(recipients, pgp.NewPGP())
			}
			// PGP clear
			enc, err := pgp.Encrypt(msg, recipients, false)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Println("Id created ", recipients[len(recipients)-1].Public.Fingerprint)
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			m := newMonitor()
			_, err = recipients[len(recipients)-1].Decrypt(enc)
			tPGPclear = append(tPGPclear, m.record())
			if err != nil {
				log.Fatal(err)
			}

			//---------------- PGP hidden -------------------
			enc, err = pgp.Encrypt(msg, recipients, true)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			m.reset()
			_, err = recipients[len(recipients)-1].Decrypt(enc)
			tPGPhidden = append(tPGPhidden, m.record())
			if err != nil {
				log.Fatal(err)
			}

			// ----------- PURBs simplified ---------------
			fmt.Println("Message is", msg)
			publicFixedParams := NewPublicFixedParameters(si, true)
			purb, err := Encode(msg, decs, random.New(), publicFixedParams, simulationIsVerbose)
			blob := purb.ToBytes()
			if err != nil {
				panic(err.Error())
			}
			m.reset()
			success, out, err := Decode(blob, &decs[0], publicFixedParams, simulationIsVerbose)
			tPURBs = append(tPURBs, m.record())

			fmt.Println("Message was", msg)
			fmt.Println("out is", out)
			fmt.Println("success is", success)
			fmt.Println("They equal", bytes.Equal(msg, out))

			if !success || !bytes.Equal(out, msg) {
				panic("PURBs did not decrypt correctly")
			}
			if err != nil {
				panic(err.Error())
			}

			// ----------------- PURBs --------------------
			publicFixedParams = NewPublicFixedParameters(si, false)
			purb, err = Encode(msg, decs, random.New(), publicFixedParams, true)
			blob = purb.ToBytes()
			if err != nil {
				panic(err.Error())
			}
			m.reset()
			success, out, err = Decode(blob, &decs[0], publicFixedParams, true)
			tPURBhash = append(tPURBhash, m.record())

			fmt.Println("Message was", msg)
			fmt.Println("out is", out)
			fmt.Println("success is", success)
			fmt.Println("They equal", bytes.Equal(msg, out))

			if !success || !bytes.Equal(out, msg) {
				panic("PURBs did not decrypt correctly")
			}
			if err != nil {
				panic(err.Error())
			}
		}
		//fmt.Printf("Results for PGP clear: %v \nResults for PGP hidden: %v\nResults for PURBs hash tabled: %v\n",
		//	tPGPclear, tPGPhidden, tPURBhash)
		f.WriteString(strings.Trim(fmt.Sprint(tPGPclear), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(tPGPhidden), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(tPURBs), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(tPURBhash), "[]") + "\n")
	}
}

// SimulMeasureHeaderSize
func SimulMeasureHeaderSize() {
	// File to write results to
	f, err := os.Create("simul_header_size.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	si := createInfo()
	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, AEAD_NONCE_LENGTH)
	random.Bytes(key, random.New())
	random.Bytes(nonce, random.New())
	nums := []int{1, 3, 10, 30, 100, 300, 1000, 3000}
	//nums := []int{1, 10}
	f.WriteString(strings.Trim(fmt.Sprint(nums), "[]") + "\n")
	for _, N := range nums {
		var flat, slack1, slack3, slack10 []int
		f.WriteString(fmt.Sprint(N) + "\n")
		log.Println(N)
		decs := createDecoders(N)
		for k := 0; k < 21; k++ {
			log.Println("Iteration ", k)
			// Baseline
			// create the PURB datastructure

			publicFixedParams := NewPublicFixedParameters(si, false)

			p := &Purb{
				Nonce:            nonce,
				Header:           nil,
				Payload:          nil,
				PayloadKey:       key,
				IsVerbose:        false,
				Recipients:       decs,
				Stream:           random.New(),
				OriginalData:     nil,
				PublicParameters: publicFixedParams,
			}

			p.CreateHeader()
			flat = append(flat, p.Header.Length())

			// 1 attempt
			p.PublicParameters.HashTableCollisionLinearResolutionAttempts = 1
			p.Header = nil
			p.CreateHeader()
			slack1 = append(slack1, p.Header.Length())
			// 3 attempts
			p.PublicParameters.HashTableCollisionLinearResolutionAttempts = 3
			p.Header = nil
			p.CreateHeader()
			slack3 = append(slack3, p.Header.Length())
			// 10 attempts
			p.PublicParameters.HashTableCollisionLinearResolutionAttempts = 10
			p.Header = nil
			p.CreateHeader()
			slack10 = append(slack10, p.Header.Length())
		}
		f.WriteString(strings.Trim(fmt.Sprint(flat), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack1), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack3), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack10), "[]") + "\n")
	}
}

// SimulMeasureEncryptionTime
func SimulMeasureEncryptionTime() {

	// File to write results to
	f, err := os.Create("simul_encryption_time.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	msg := simulGetRandomBytes(100)

	log.Printf("Length of the message is %d bytes\n", len(msg))

	nsuites := []int{1, 3, 10}
	recs := []int{1, 3, 10, 100}
	fmt.Println(strings.Trim(fmt.Sprint(recs), "[]"))
	for _, nsuite := range nsuites {
		fmt.Println("Suites =", nsuite)
		si := createMultiInfo(nsuite)
		publicFixedParams := NewPublicFixedParameters(si, false)

		for _, N := range recs {
			if N < nsuite {
				continue
			}
			decs := createMultiDecoders(N, si)
			m := newMonitor()
			for i := 0; i < 21; i++ {
				_, err := Encode(msg, decs, random.New(), publicFixedParams, simulationIsVerbose)
				val := m.recordAndReset()
				fmt.Printf("%f\n", val)
				f.WriteString(fmt.Sprintf("%f\n", val))
				if err != nil {
					panic(err.Error())
				}
			}
		}
	}
}

// SimulDecodeOne decodes 1 purb
func SimulDecodeOne() {

	msg := simulGetRandomBytes(100)
	si := createInfo()
	publicFixedParams := NewPublicFixedParameters(si, simulationUsesSimplifiedLayout)
	decs := createDecoders(1)
	purb, err := Encode(msg, decs, random.New(), publicFixedParams, simulationIsVerbose)
	if err != nil {
		panic(err.Error())
	}
	blob := purb.ToBytes()
	Decode(blob, &decs[0], publicFixedParams, simulationIsVerbose)

	//PGP
	//sender := NewPGP()
	recipients := make([]*pgp.PGP, 1)
	recipients[0] = pgp.NewPGP()
	enc, err := pgp.Encrypt(msg, recipients, false)
	log.Println(pgp.ArmorEncryption(enc))
	if err != nil {
		log.Fatal(err)
	}
	_, err = recipients[len(recipients)-1].Decrypt(enc)
}

func createInfo() SuiteInfoMap {
	info := make(SuiteInfoMap)
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &SuiteInfo{
		AllowedPositions:  []int{12 + 0*CORNERSTONE_LENGTH, 12 + 1*CORNERSTONE_LENGTH, 12 + 3*CORNERSTONE_LENGTH, 12 + 4*CORNERSTONE_LENGTH},
		CornerstoneLength: CORNERSTONE_LENGTH}
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

func createMultiInfo(N int) SuiteInfoMap {
	info := make(SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := AEAD_NONCE_LENGTH
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*CORNERSTONE_LENGTH
			floor += int(math.Pow(2, float64(i))) * CORNERSTONE_LENGTH
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &SuiteInfo{
			AllowedPositions: positions[i], CornerstoneLength: CORNERSTONE_LENGTH}
	}

	return info
}

func createMultiDecoders(n int, si SuiteInfoMap) []Recipient {
	type suite struct {
		Name  string
		Value Suite
	}
	decs := make([]Recipient, 0)
	suites := make([]suite, 0)
	for name := range si {
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
