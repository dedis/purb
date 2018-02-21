package simul

import (
	"fmt"
	"time"
	"gopkg.in/dedis/crypto.v0/edwards"
	"github.com/nikirill/purbs/purb"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/random"
	"bytes"
	"os"
	"strings"
	"log"
)

func MeasureNumRecipients() {
	msg := []byte("And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")

	nums := []int{1, 3, 5, 10, 30, 70, 100, 1000, 3000, 10000}
	//nums := []int{1, 3, 5, 10, 30, 70, 100}
	//nums := []int{10000}
	// File to write results to
	f, err := os.Create("simulation/results/num_recipients_ex.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(strings.Trim(fmt.Sprint(nums), "[]") + "\n")
	for _, N := range nums {
		var tPGPclear, tPGPhidden, tPURBs, tPURBhash []float64
		si := createInfo()
		decs := createDecoders(N)
		f.WriteString(fmt.Sprint(N) + "\n")
		log.Println(N)
		for k := 0; k < 21; k++ {
			log.Println("Iteration ", k)
			//------------------- PGP -------------------
			sender := NewPGP()
			recipients := make([]*PGP, 0)
			for i := 0; i < N; i++ {
				recipients = append(recipients, NewPGP())
			}
			// PGP clear
			enc, err := sender.Encrypt(msg, recipients, false)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			start := time.Now()
			_, err = recipients[len(recipients)/2].Decrypt(enc)
			t := time.Now()
			tPGPclear = append(tPGPclear, float64(t.Sub(start).Nanoseconds())/1e6)
			if err != nil {
				log.Fatal(err)
			}

			//---------------- PGP hidden -------------------
			enc, err = sender.Encrypt(msg, recipients, true)
			if err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
			start = time.Now()
			_, err = recipients[len(recipients)/2].Decrypt(enc)
			t = time.Now()
			tPGPhidden = append(tPGPhidden, float64(t.Sub(start).Nanoseconds())/1e6)
			if err != nil {
				log.Fatal(err)
			}

			// ----------- PURBs simplified ---------------
			blob, err := purb.MakePurb(msg, decs, si, purb.STREAM, true, random.Stream)
			if err != nil {
				panic(err.Error())
			}
			start = time.Now()
			success, out, err := purb.Decode(blob, &decs[len(decs)/2], purb.STREAM, true, si)
			t = time.Now()
			tPURBs = append(tPURBs, float64(t.Sub(start).Nanoseconds())/1e6)

			if !success || !bytes.Equal(out, msg) {
				panic("PURBs did not decrypt correctly")
			}
			if err != nil {
				panic(err.Error())
			}

			// ----------------- PURBs --------------------
			blob, err = purb.MakePurb(msg, decs, si, purb.STREAM, false, random.Stream)
			if err != nil {
				panic(err.Error())
			}
			start = time.Now()
			success, out, err = purb.Decode(blob, &decs[len(decs)/2], purb.STREAM, false, si)
			t = time.Now()
			tPURBhash = append(tPURBhash, float64(t.Sub(start).Nanoseconds())/1e6)

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
	key := random.Bytes(purb.SYMKEYLEN, random.Stream)
	nonce := random.Bytes(purb.NONCE_LEN, random.Stream)
	//nums := []int{1, 3, 10, 30, 100, 3000}
	nums := []int{300}
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
			p.ConstructHeader(decs, si, purb.STREAM, true, random.Stream)
			flat = append(flat, p.Header.Length)

			// 1 attempt
			purb.PLACEMENT_ATTEMPTS = 1
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.Stream)
			slack1 = append(slack1, p.Header.Length)
			// 3 attempts
			purb.PLACEMENT_ATTEMPTS = 3
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.Stream)
			slack3 = append(slack3, p.Header.Length)
			// 10 attempts
			purb.PLACEMENT_ATTEMPTS = 10
			p.Header = nil
			p.ConstructHeader(decs, si, purb.STREAM, false, random.Stream)
			slack10 = append(slack10, p.Header.Length)
		}
		f.WriteString(strings.Trim(fmt.Sprint(flat), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack1), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack3), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack10), "[]") + "\n")
	}
}

func createInfo() purb.SuiteInfoMap {
	info := make(purb.SuiteInfoMap)
	info[edwards.NewAES128SHA256Ed25519(true).String()] = &purb.SuiteInfo{
		Positions: []int{12 + 0*purb.KEYLEN, 12 + 1*purb.KEYLEN, 12 + 3*purb.KEYLEN, 12 + 4*purb.KEYLEN},
		KeyLen:    purb.KEYLEN,}
	//info[ed25519.NewAES128SHA256Ed25519(true).String()] = &SuiteInfo{
	//	Positions: []int{0, 40, 160},
	//	KeyLen:    KEYLEN,}
	return info
}

func createDecoders(n int) []purb.Decoder {
	decs := make([]purb.Decoder, 0)
	//suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true), ed25519.NewAES128SHA256Ed25519(true)}
	suites := []abstract.Suite{edwards.NewAES128SHA256Ed25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := config.NewKeyPair(suite)
			decs = append(decs, purb.Decoder{Suite: suite, PublicKey: pair.Public, PrivateKey: pair.Secret})
		}
	}
	return decs
}