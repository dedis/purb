package main

import (
	"github.com/dedis/purbs/purbs"
)

func main() {
	// TODO: LB: restore this. I am not sure what goes wrong, as "purb_test.go" does the same and succeeds
	//purbs.SimulMeasureNumRecipients()
	purbs.SimulMeasureHeaderSize()
	purbs.SimulMeasureEncryptionTime()
	purbs.SimulDecodeOne()
}