package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"os"
	"strings"

	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/paper_purbs/experiments-encoding/pgp"
	"github.com/dedis/paper_purbs/purbs"
)

const VERBOSE = false
const SIMPLIFIED_PURB = false
const ENTRYPOINT_TYPE = purbs.STREAM

func main() {
	//MeasureNumRecipients()
	//MeasureHeaderSize()
	//MeasureEncryptionTime()
	DecodeOne()
}

func MeasureNumRecipients() {
	msg := []byte("“Are you quite, quite sure that—well," +
		"not tomorrow, of course, and not after tomorrow, but—well—some day, any day," +
		"you will not come to live with me? I will create a brand new God and thank him with piercing" +
		"cries, if you give me that microscopic hope”" +
		"“No,” she said smiling, “no.”" +
		"“It would have made all the difference,” said Humbert Humbert." +
		"Then I pulled out my automatic—I mean, this is the kind of fool thing " +
		"a reader might suppose I did. It never even occurred to me to do it." +
		"“Good by-aye!” she chanted, my American sweet immortal dead love; for she is dead" +
		"and immortal if you are reading this. I mean, such is the formal agreement with the so-called authorities." +
		"Then, as I drove away, I heard her shout in a vibrant voice to her Dick;" +
		"and the dog started to lope alongside my car like a fat " +
		"dolphin, but he was too heavy and old, and very soon gave up. " +
		"And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")

	log.Printf("Length of the message is %d bytes\n", len(msg))
	nums := []int{1, 3, 5, 10, 30, 70, 100, 1000, 3000, 10000}
	//nums := []int{1, 3, 5, 10, 30, 70, 100}
	//nums := []int{1000, 3000, 10000}
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
			publicFixedParams := purbs.NewPublicFixedParameters(si, ENTRYPOINT_TYPE, true)
			purb, err := purbs.Encode(msg, decs, random.New(), publicFixedParams, VERBOSE)
			blob := purb.ToBytes()
			if err != nil {
				panic(err.Error())
			}
			m.reset()
			success, out, err := purbs.Decode(blob, &decs[0], publicFixedParams, VERBOSE)
			tPURBs = append(tPURBs, m.record())

			if !success || !bytes.Equal(out, msg) {
				panic("PURBs did not decrypt correctly")
			}
			if err != nil {
				panic(err.Error())
			}

			// ----------------- PURBs --------------------
			publicFixedParams = purbs.NewPublicFixedParameters(si, ENTRYPOINT_TYPE, false)
			purb, err = purbs.Encode(msg, decs, random.New(), publicFixedParams, VERBOSE)
			blob = purb.ToBytes()
			if err != nil {
				panic(err.Error())
			}
			m.reset()
			success, out, err = purbs.Decode(blob, &decs[0], publicFixedParams, VERBOSE)
			tPURBhash = append(tPURBhash, m.record())

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
	f, err := os.Create("simulation/results/header_size.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	si := createInfo()
	key := make([]byte, purbs.SYMMETRIC_KEY_LENGTH)
	nonce := make([]byte, purbs.AEAD_NONCE_LENGTH)
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

			publicFixedParams := purbs.NewPublicFixedParameters(si, ENTRYPOINT_TYPE, false)

			p := &purbs.Purb{
				Nonce:      nonce,
				Header:     nil,
				Payload:    nil,
				PayloadKey: key,
				IsVerbose:       false,
				Recipients:      decs,
				Stream:          random.New(),
				OriginalData:    nil,
				PublicParameters: publicFixedParams,
			}

			p.ConstructHeader()
			flat = append(flat, p.Header.Length)

			// 1 attempt
			purbs.HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS = 1
			p.Header = nil
			p.ConstructHeader()
			slack1 = append(slack1, p.Header.Length)
			// 3 attempts
			purbs.HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS = 3
			p.Header = nil
			p.ConstructHeader()
			slack3 = append(slack3, p.Header.Length)
			// 10 attempts
			purbs.HASHTABLE_COLLISION_LINEAR_PLACEMENT_ATTEMPTS = 10
			p.Header = nil
			p.ConstructHeader()
			slack10 = append(slack10, p.Header.Length)
		}
		f.WriteString(strings.Trim(fmt.Sprint(flat), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack1), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack3), "[]") + "\n")
		f.WriteString(strings.Trim(fmt.Sprint(slack10), "[]") + "\n")
	}
}

func MeasureEncryptionTime() {
	msg := []byte("“Are you quite, quite sure that—well," +
		"not tomorrow, of course, and not after tomorrow, but—well—some day, any day," +
		"you will not come to live with me? I will create a brand new God and thank him with piercing" +
		"cries, if you give me that microscopic hope”" +
		"“No,” she said smiling, “no.”" +
		"“It would have made all the difference,” said Humbert Humbert." +
		"Then I pulled out my automatic—I mean, this is the kind of fool thing " +
		"a reader might suppose I did. It never even occurred to me to do it." +
		"“Good by-aye!” she chanted, my American sweet immortal dead love; for she is dead" +
		"and immortal if you are reading this. I mean, such is the formal agreement with the so-called authorities." +
		"Then, as I drove away, I heard her shout in a vibrant voice to her Dick;" +
		"and the dog started to lope alongside my car like a fat " +
		"dolphin, but he was too heavy and old, and very soon gave up. " +
		"And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")
	log.Printf("Length of the message is %d bytes\n", len(msg))

	nsuites := []int{1, 3, 10}
	recs := []int{1, 3, 10, 100}
	fmt.Println(strings.Trim(fmt.Sprint(recs), "[]"))
	for _, nsuite := range nsuites {
		fmt.Println("Suites =", nsuite)
		si := createMultiInfo(nsuite)
		publicFixedParams := purbs.NewPublicFixedParameters(si, ENTRYPOINT_TYPE, false)

		for _, N := range recs {
			if N < nsuite {
				continue
			}
			decs := createMultiDecoders(N, si)
			m := newMonitor()
			for i := 0; i < 21; i++ {
				_, err := purbs.Encode(msg, decs, random.New(), publicFixedParams, VERBOSE)
				fmt.Printf("%f\n", m.recordAndReset())
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
	publicFixedParams := purbs.NewPublicFixedParameters(si, ENTRYPOINT_TYPE, SIMPLIFIED_PURB)
	decs := createDecoders(1)
	purb, err := purbs.Encode(msg, decs, random.New(), publicFixedParams, VERBOSE)
	if err != nil {
		panic(err.Error())
	}
	blob := purb.ToBytes()
	purbs.Decode(blob, &decs[0], publicFixedParams, VERBOSE)

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

func createInfo() purbs.SuiteInfoMap {
	info := make(purbs.SuiteInfoMap)
	info[curve25519.NewBlakeSHA256Curve25519(true).String()] = &purbs.SuiteInfo{
		AllowedPositions: []int{12 + 0*purbs.CORNERSTONE_LENGTH, 12 + 1*purbs.CORNERSTONE_LENGTH, 12 + 3*purbs.CORNERSTONE_LENGTH, 12 + 4*purbs.CORNERSTONE_LENGTH},
		CornerstoneLength:    purbs.CORNERSTONE_LENGTH}
	return info
}

func createDecoders(n int) []purbs.Recipient {
	decs := make([]purbs.Recipient, 0)
	suites := []purbs.Suite{curve25519.NewBlakeSHA256Curve25519(true)}
	for _, suite := range suites {
		for i := 0; i < n; i++ {
			pair := key.NewKeyPair(suite)
			decs = append(decs, purbs.Recipient{SuiteName: suite.String(), Suite: suite, PublicKey: pair.Public, PrivateKey: pair.Private})
		}
	}
	return decs
}

func createMultiInfo(N int) purbs.SuiteInfoMap {
	info := make(purbs.SuiteInfoMap)
	positions := make([][]int, N+1)
	suffixes := []string{"", "a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for k := 0; k < N; k++ {
		limit := int(math.Ceil(math.Log2(float64(N)))) + 1
		positions[k] = make([]int, limit)
		floor := purbs.AEAD_NONCE_LENGTH
		for i := 0; i < limit; i++ {
			positions[k][i] = floor + k%int(math.Pow(2, float64(i)))*purbs.CORNERSTONE_LENGTH
			floor += int(math.Pow(2, float64(i))) * purbs.CORNERSTONE_LENGTH
		}
		//log.Println(positions[k])
	}
	for i := 0; i < N; i++ {
		info[curve25519.NewBlakeSHA256Curve25519(true).String()+suffixes[i]] = &purbs.SuiteInfo{
			AllowedPositions: positions[i], CornerstoneLength: purbs.CORNERSTONE_LENGTH}
	}

	return info
}

func createMultiDecoders(n int, si purbs.SuiteInfoMap) []purbs.Recipient {
	type suite struct {
		Name  string
		Value purbs.Suite
	}
	decs := make([]purbs.Recipient, 0)
	suites := make([]suite, 0)
	for name := range si {
		suites = append(suites, suite{name, curve25519.NewBlakeSHA256Curve25519(true)})
	}
	for n > 0 {
		for _, suite := range suites {
			pair := key.NewHidingKeyPair(suite.Value)
			decs = append(decs, purbs.Recipient{SuiteName: suite.Name, Suite: suite.Value, PublicKey: pair.Public, PrivateKey: pair.Private})
			n -= 1
			if n == 0 {
				break
			}
		}
	}
	return decs
}
