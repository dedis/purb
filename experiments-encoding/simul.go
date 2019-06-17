package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/purbs/purbs"
	"gopkg.in/urfave/cli.v1"
)

const REPEAT = 20
const RECIPIENTS_HEADER_STR = "1,10,100" //100,1000,10000"
const RECIPIENTS_ENCODING_STR = "1,3,10,100" //100,1000,10000"
const RECIPIENTS_DECODING_STR = "1,10,100,1000,10000"
const SUITES_ENCODING_STR = "1,3,10"
const SUITES_DECODING_STR = "1"

func main() {
	app := cli.NewApp()
	app.Name = "purbs simul"
	app.Version = "0.1"
	app.Commands = []cli.Command{
		{
			Name:    "decode",
			Aliases: []string{"d"},
			Action:  decoding,
		},
		{
			Name:    "header",
			Aliases: []string{"h"},
			Action:  headerSize,
		},
		{
			Name: "encode",
			Aliases: []string{"e"},
			Action: encoding,
		},
		{
			Name: "compactness",
			Aliases: []string{"c"},
			Action: headerCompactness,
		},
	}
	app.Run(os.Args)
}

func decoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_DECODING_STR)
	suites := toIntArray(SUITES_DECODING_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing decoding time for various number of recipients/suites")
	out := purbs.SimulMeasureWorstDecodingTime(REPEAT, recipients, suites)
	fmt.Println(out)
}

func encoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_ENCODING_STR)
	suites := toIntArray(SUITES_ENCODING_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Precise Encoding times for various number of recipients/suites")
	out := purbs.SimulMeasureEncodingTime(REPEAT, recipients, suites)
	fmt.Println(out)
}

func headerSize(c *cli.Context){
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_HEADER_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Header size for various number of recipients")
	out := purbs.SimulMeasureHeaderSize(REPEAT, recipients)
	fmt.Println(out)
}


func headerCompactness(c *cli.Context){
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_HEADER_STR)
	suites := toIntArray(SUITES_ENCODING_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Header compactness for various number of recipients/suites")
	out := purbs.SimulMeasureHeaderCompactness(REPEAT, recipients, suites)
	fmt.Println(out)
}

func toIntArray(str string) []int {
	parts := strings.Split(str, ",")
	r := make([]int, len(parts))

	for j := 0; j < len(parts); j++ {
		i, err := strconv.Atoi(parts[j])
		if err != nil {
			panic(err)
		}
		r[j] = i
	}

	return r
}