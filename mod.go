// Package purb defines the logger.
package purb

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

type Purb interface {
	// Encode a PURB blob from some data and recipients information
	Encode(data []byte) error

	// ToBytes get the []byte representation of the encoded PURB blob
	ToBytes() []byte

	// Decode takes a PURB blob and a recipient information (suite+KeyPair) and extracts the payload
	Decode(blob []byte) (bool, []byte, error)

	// VisualRepresentation returns a string with the internal details of the PURB blob
	VisualRepresentation() string
}

// purb is using a global logger with some default parameters. It is disabled by
// default and the level can be increased using an environment variable:
//
//	LLVL=trace go test ./...
//	LLVL=info go test ./...
//	LLVL=debug LOGF=$HOME/dela.log go test ./...

// EnvLogLevel is the name of the environment variable to change the logging
// level.
const EnvLogLevel = "LLVL"

// EnvLogFile is the name of the environment variable to log in a given file.
const EnvLogFile = "LOGF"

const defaultLevel = zerolog.NoLevel

func init() {
	logLevel := os.Getenv(EnvLogLevel)

	var level zerolog.Level

	switch logLevel {
	case "error":
		level = zerolog.ErrorLevel
	case "warn":
		level = zerolog.WarnLevel
	case "info":
		level = zerolog.InfoLevel
	case "debug":
		level = zerolog.DebugLevel
	case "trace":
		level = zerolog.TraceLevel
	case "":
		level = defaultLevel
	default:
		level = zerolog.TraceLevel
	}

	Logger = Logger.Level(level)

	logFile := os.Getenv(EnvLogFile)
	if len(logFile) > 3 {
		fileOut, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			Logger.Error().Msgf("COULD NOT OPEN %v", logFile)
			os.Exit(2)
		}

		multiWriter := zerolog.MultiLevelWriter(fileOut, consoleOut)
		Logger = Logger.Output(multiWriter)
		Logger.Info().Msgf("Using log file: %v", logFile)
	}

	Logger.Info().Msgf("PURB Logger initialized!")
}

var consoleOut = zerolog.ConsoleWriter{
	Out:        os.Stdout,
	TimeFormat: time.RFC3339,
}

// Logger is a globally available logger instance. By default, it only prints
// error level messages but it can be changed through a environment variable.
var Logger = zerolog.New(consoleOut).Level(defaultLevel).
	With().Timestamp().Logger().
	With().Caller().Logger()
