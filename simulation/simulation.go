package simul

import (
	"fmt"
	"time"
	"bytes"
	"os"
	"strings"
	"log"
	"math"

	"github.com/nikirill/purbs/purb"

	"gopkg.in/dedis/kyber.v2/util/random"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/kyber.v2/group/curve25519"
)

func MeasureNumRecipients() {
	msg := []byte("And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")

	nums := []int{1, 3, 5, 10, 30, 70, 100, 1000, 3000, 10000}
	//nums := []int{1, 3, 5, 10, 30, 70, 100}
	//nums := []int{100}
	// File to write results to
	f, err := os.Create("simulation/results/num_recipients_ex.txt")
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
			recipients := make([]*PGP, 0)
			for i := 0; i < N; i++ {
				recipients = append(recipients, NewPGP())
			}
			// PGP clear
			enc, err := Encrypt(msg, recipients, false)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Println("Id created ", recipients[len(recipients)-1].Public.Fingerprint)
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			m := purb.NewMonitor()
			_, err = recipients[len(recipients)-1].Decrypt(enc)
			tPGPclear = append(tPGPclear, m.Record())
			if err != nil {
				log.Fatal(err)
			}

			//---------------- PGP hidden -------------------
			enc, err = Encrypt(msg, recipients, true)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			m.Reset()
			_, err = recipients[len(recipients)-1].Decrypt(enc)
			tPGPhidden = append(tPGPhidden, m.Record())
			if err != nil {
				log.Fatal(err)
			}

			// ----------- PURBs simplified ---------------
			blob, err := purb.MakePurb(msg, decs, si, purb.STREAM, true, random.New())
			if err != nil {
				panic(err.Error())
			}
			m.Reset()
			success, out, err := purb.Decode(blob, &decs[len(decs)-1], purb.STREAM, true, si)
			tPURBs = append(tPURBs, m.Record())

			if !success || !bytes.Equal(out, msg) {
				panic("PURBs did not decrypt correctly")
			}
			if err != nil {
				panic(err.Error())
			}

			// ----------------- PURBs --------------------
			blob, err = purb.MakePurb(msg, decs, si, purb.STREAM, false, random.New())
			if err != nil {
				panic(err.Error())
			}
			m.Reset()
			success, out, err = purb.Decode(blob, &decs[len(decs)-1], purb.STREAM, false, si)
			tPURBhash = append(tPURBhash, m.Record())

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

func MeasureHeaderSize() {
	// File to write results to
	f, err := os.Create("simulation/results/header_size_ex.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	si := createInfo()
	key := make([]byte, purb.SYMKEYLEN)
	nonce := make([]byte, purb.NONCE_LEN)
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
			p, err := purb.NewPurb(key, nonce)
			if err != nil {
				log.Fatalln(err)
			}
			p.ConstructHeader(decs, si, purb.STREAM, true, random.New())
			flat = append(flat, p.Header.Length)

			// 1 attempt
			purb.PLACEMENT_ATTEMPTS = 1
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.New())
			slack1 = append(slack1, p.Header.Length)
			// 3 attempts
			purb.PLACEMENT_ATTEMPTS = 3
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.New())
			slack3 = append(slack3, p.Header.Length)
			// 10 attempts
			purb.PLACEMENT_ATTEMPTS = 10
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.New())
			slack10 = append(slack10, p.Header.Length)
		}
		f.WriteString(strings.Trim(fmt.Sprint(flat), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack1), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack3), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack10), "[]") + "\n")
	}
}

func MeasureEncryptionTime() {
	msg := []byte("And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")
	log.Printf("Length of the message is %d bytes\n", len(msg))
	purb.EXPRM = true
	nsuites := []int{1, 3, 10}
	recs := []int{1, 3, 10, 100}
	fmt.Println(strings.Trim(fmt.Sprint(recs), "[]"))
	for _, nsuite := range nsuites {
		fmt.Println("Suites =", nsuite)
		si := createMultiInfo(nsuite)
		for _, N := range recs {
			if N < nsuite {
				continue
			}
			decs := createMultiDecoders(N, si)
			m := purb.NewMonitor()
			for i := 0; i < 21; i++ {
				_, err := purb.MakePurb(msg, decs, si, purb.STREAM, false, random.New())
				fmt.Printf("%f\n", m.RecordAndReset())
				if err != nil {
					panic(err.Error())
				}
			}
		}
	}
}

func DecodeOne() {
	msg := []byte("And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")
	si := createInfo()
	decs := createDecoders(1)
	blob, err := purb.MakePurb(msg, decs, si, purb.STREAM, false, random.New())
	if err != nil {
		panic(err.Error())
	}
	start := time.Now()
	purb.Decode(blob, &decs[0], purb.STREAM, false, si)
	fmt.Println("Total time ", time.Since(start))

	//PGP
	//sender := NewPGP()
	recipients := make([]*PGP, 1)
	recipients[0] = NewPGP()
	enc, err := Encrypt(msg, recipients, false)
	if err != nil {
		log.Fatal(err)
	}
	_, err = recipients[len(recipients)-1].Decrypt(enc)
}

func createInfo() purb.SuiteInfoMap {
	info := make(purb.SuiteInfoMap)
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &purb.SuiteInfo{
		Positions: []int{12 + 0*purb.KEYLEN, 12 + 1*purb.KEYLEN, 12 + 3*purb.KEYLEN, 12 + 4*purb.KEYLEN},
		KeyLen:    purb.KEYLEN,}
	return info
}

func createDecoders(n int) []purb.Decoder {
	decs := make([]purb.Decoder, 0)
	suites := []purb.Suite{curve25519.NewBlakeSHA256Curve25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := key.NewKeyPair(suite)
			decs = append(decs, purb.Decoder{SuiteName: suite.String(), Suite: suite, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}

func createMultiInfo(N int) purb.SuiteInfoMap {
	info := make(purb.SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := purb.NONCE_LEN
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*purb.KEYLEN
			floor += int(math.Pow(2, float64(i))) * purb.KEYLEN
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &purb.SuiteInfo{
			Positions: positions[i], KeyLen: purb.KEYLEN,}
	}

	return info
}

func createMultiDecoders(n int, si purb.SuiteInfoMap) []purb.Decoder {
	type suite struct {
		Name  string
		Value purb.Suite
	}
	decs := make([]purb.Decoder, 0)
	suites := make([]suite, 0)
	for name := range si {
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for i := 0; i < n; i++ {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, purb.Decoder{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}
