package main

import (
	"github.com/dedis/purbs/purbs"
	"gopkg.in/urfave/cli.v1"
	"fmt"
	"os"
	"log"
)

const REPEAT = 2
const PAYLOAD_SIZE = 100

func main() {
	app := cli.NewApp()
	app.Name = "purbs simul"
	app.Version = "0.1"
	app.Commands = []cli.Command{
		{
			Name:    "encode",
			Aliases: []string{"e"},
			Action:  encoding,
		},
		{
			Name:    "decode",
			Aliases: []string{"d"},
			Action:  decoding,
		},
		{
			Name:    "decodePGP",
			Aliases: []string{"g"},
			Action:  decoding,
		},
		{
			Name:    "header",
			Aliases: []string{"h"},
			Action:  headerSize,
		},
	}
	app.Run(os.Args)
}

func encoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := []int{1,3,10,30}//,100,300,1000,3000}
	suites := []int{1,3,10}

	l.Println("-------------------------------------------------------")
	l.Println("Computing Encoding times for various number of recipients/suites")
	out := purbs.SimulMeasureEncodingTime(REPEAT, recipients, suites)
	fmt.Println(out)
}

func headerSize(c *cli.Context){
	l := log.New(os.Stderr, "", 0)

	recipients := []int{1,3,10,30} //,100,300,1000,3000}

	l.Println("-------------------------------------------------------")
	l.Println("Computing Header size for various number of recipients")
	out := purbs.SimulMeasureHeaderSize(REPEAT, recipients)
	fmt.Println(out)
}

func decoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := []int{1,3,10,30}//,100,300,1000,3000}

	l.Println("-------------------------------------------------------")
	l.Println("Computing Decoding time for various number of recipients")
	out := purbs.SimulDecode(REPEAT, PAYLOAD_SIZE, recipients)
	fmt.Println(out)
}

func decodingPGP(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := []int{1,3,10,30} //,100,300,1000,3000}

	l.Println("-------------------------------------------------------")
	l.Println("Computing PGP-Decoding time for various number of recipients")
	out := purbs.SimulDecodePGP(REPEAT, PAYLOAD_SIZE, recipients)
	fmt.Println(out)
}