package simul

import (
	"fmt"
	"log"
	"time"
)

func MeasureNumRecipients() {
	msg := []byte("And presently I was driving through the drizzle of the dying day, " +
		"with the windshield wipers in full action but unable to cope with my tears.")
	sender := NewPGP()
	recipients := make([]*PGP, 0)
	for i:=0; i<10000; i++ {
		recipients = append(recipients, NewPGP())
	}
	enc, err := sender.Encrypt(msg, recipients)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("Encryption:\n%s\n", sender.ArmorEncryption(enc))
	start := time.Now()
	_, err = recipients[len(recipients) - 1].Decrypt(enc)
	t := time.Now()
	elapsedPGP := t.Sub(start)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Time taken by operations: ", elapsedPGP)
}