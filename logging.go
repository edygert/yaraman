package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type customLogWriter struct {
	writer   zerolog.LevelWriter
	minLevel zerolog.Level
	maxLevel zerolog.Level
}

var (
	logger      zerolog.Logger
	errorLogger zerolog.Logger
)

func (w *customLogWriter) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *customLogWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level >= w.minLevel && level <= w.maxLevel {
		return w.writer.WriteLevel(level, p)
	}
	return len(p), nil
}

func initLogging(ctx *YaramanContext) bool {
	var (
		err         error
		errorFile   *os.File
		debugFile   *os.File
		yaramanFile *os.File
		writer      zerolog.LevelWriter
	)

	err = os.MkdirAll(ctx.logDir, 0755)
	if err != nil {
		log.Fatal().AnErr("error", err).Str("directory", ctx.logDir).Msg("Could not create logging directory.")
	}
	errorFile, err = os.OpenFile(makeFullPath(ctx.logDir, "error.json"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal().AnErr("error", err).Str("filename", "error.json").Msg("Could not open log file.")
	}
	yaramanFile, err = os.OpenFile(makeFullPath(ctx.logDir, "yaraman.json"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal().AnErr("error", err).Str("filename", "yaraman.json").Msg("Could not open log file.")
	}
	if ctx.logLevel == "debug" {
		debugFile, err = os.OpenFile(makeFullPath(ctx.logDir, "debug.json"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatal().AnErr("error", err).Str("filename", "debug.json").Msg("Could not open log file.")
		}
	}

	errorWriter := zerolog.MultiLevelWriter(errorFile)
	yaramanWriter := zerolog.MultiLevelWriter(yaramanFile)

	filteredErrorWriter := &customLogWriter{
		writer:   errorWriter,
		minLevel: zerolog.ErrorLevel,
		maxLevel: zerolog.PanicLevel,
	}

	filteredYaramanWriter := &customLogWriter{
		writer:   yaramanWriter,
		minLevel: zerolog.InfoLevel,
		maxLevel: zerolog.WarnLevel,
	}

	if debugFile != nil {
		debugWriter := zerolog.MultiLevelWriter(debugFile)
		filteredDebugWriter := &customLogWriter{
			writer:   debugWriter,
			minLevel: zerolog.TraceLevel,
			maxLevel: zerolog.DebugLevel,
		}
		writer = zerolog.MultiLevelWriter(filteredErrorWriter, filteredYaramanWriter, filteredDebugWriter)
	} else {
		writer = zerolog.MultiLevelWriter(filteredErrorWriter, filteredYaramanWriter)
	}

	logger = zerolog.New(writer).With().Timestamp().Logger()
	errorLogger = logger.With().Caller().Logger()

	return true
}
