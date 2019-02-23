package main

import (
	"github.com/dedis/purbs/purbs"
	"gopkg.in/urfave/cli.v1"
	"fmt"
	"os"
	"log"
	"strings"
	"strconv"
)

const REPEAT = 20
const PAYLOAD_SIZE = 1000 * 8
const RECIPIENTS_STR = "1,10,100" //100,1000,10000"
const SUITES_STR = "1,3,10"

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
			Name:    "header",
			Aliases: []string{"h"},
			Action:  headerSize,
		},
		{
			Name: "encode-precise",
			Aliases: []string{"p"},
			Action: encodingPrecise,
		},
		{
			Name: "compactness",
			Aliases: []string{"c"},
			Action: headerCompactness,
		},
	}
	app.Run(os.Args)
}

func encoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_STR)
	suites := toIntArray(SUITES_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Encoding times for various number of recipients/suites")
	out := purbs.SimulMeasureEncodingTime(REPEAT, recipients, suites)
	fmt.Println(out)
}

func encodingPrecise(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray("1,10,100")
	suites := toIntArray(SUITES_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Precise Encoding times for various number of recipients/suites")
	out := purbs.SimulMeasureEncodingTimePrecise(REPEAT, recipients, suites)
	fmt.Println(out)
}

func headerSize(c *cli.Context){
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Header size for various number of recipients")
	out := purbs.SimulMeasureHeaderSize(REPEAT, recipients)
	fmt.Println(out)
}


func headerCompactness(c *cli.Context){
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_STR)
	suites := toIntArray(SUITES_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Header compactness for various number of recipients/suites")
	out := purbs.SimulMeasureHeaderCompactness(REPEAT, recipients, suites)
	fmt.Println(out)
}

func decoding(c *cli.Context) {
	l := log.New(os.Stderr, "", 0)

	recipients := toIntArray(RECIPIENTS_STR)

	l.Println("-------------------------------------------------------")
	l.Println("Computing Decoding time for various number of recipients")
	out := purbs.SimulDecode(REPEAT, PAYLOAD_SIZE, recipients)
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