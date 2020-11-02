package main

import (
	"os"
	"path"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	toml "github.com/pelletier/go-toml"
	"github.com/rs/zerolog/log"
)

// YaramanContext provides context for CLI handling
type YaramanContext struct {
	configFile     string
	logDir         string
	execDir        string
	databaseDir    string
	rulesDir       string
	exportDir      string
	logLevel       string
	fileExtensions MapSet
	repoHosts      MapSet
}

func makeFullPath(directory string, filename string) string {
	if strings.HasSuffix(directory, "/") || strings.HasSuffix(directory, `\`) {
		directory = directory[:len(directory)-1]
	}
	return directory + string(os.PathSeparator) + filename
}

func initialize(ctx *YaramanContext) {
	var extensions string

	if fileExists(ctx.configFile) {
		config, err := toml.LoadFile(ctx.configFile)
		if err != nil {
			log.Fatal().AnErr("error", err).Str("config_file", ctx.configFile).Msg("Could not parse configuration file.")
		}
		ctx.logDir = config.GetDefault("yaraman.log_dir", ctx.logDir).(string)
		initLogging(ctx)

		ctx.rulesDir = config.GetDefault("yaraman.rules_dir", ctx.rulesDir).(string)
		ctx.databaseDir = config.GetDefault("yaraman.database_dir", ctx.databaseDir).(string)
		ctx.exportDir = config.GetDefault("yaraman.export_dir", ctx.exportDir).(string)

		extensions = config.GetDefault("yaraman.file_extensions", "yara,yar").(string)
		// Only use the config file extensions if they were not specified on the command line
		if extensions != "" && len(ctx.fileExtensions) == 0 {
			ctx.fileExtensions = MapSet{}
			for _, extension := range strings.Split(extensions, ",") {
				ctx.fileExtensions.Add(extension)
			}
		}

		repoHosts := config.GetDefault("yaraman.repo_hosts", "github.com").(string)
		hosts := strings.Split(repoHosts, ";")
		for _, host := range hosts {
			ctx.repoHosts.Add(host)
		}
	} else {
		initLogging(ctx)
		logger.Info().Msg("No configuration file, using default settings.")
	}
	if len(ctx.fileExtensions) == 0 {
		ctx.fileExtensions.Add("yara")
		ctx.fileExtensions.Add("yar")
	}
	if len(ctx.repoHosts) == 0 {
		ctx.repoHosts.Add("github.com")
	}
	logger.Debug().Msgf("%v", ctx)

	loc, err := time.LoadLocation("UTC")
	if err != nil {
		logger.Fatal().AnErr("error", err).Msg("Could not load UTC location.")
	}
	time.Local = loc

	if !fileExists(makeFullPath(ctx.execDir, "normalized_tags.txt")) {
		logger.Fatal().Str("filename", makeFullPath(ctx.execDir, "normalized_tags.txt")).Msg("File not found")
	}
	readNormalizedMetaTags(makeFullPath(ctx.execDir, "normalized_tags.txt"))
}

func main() {
	// reflection example
	//	examiner(reflect.TypeOf(yaraDocType{}), 0)
	execDir, _ := os.Executable()
	execDir = path.Dir(execDir)
	defaultConfigFile := makeFullPath(execDir, "yaraman.toml")

	kongContext := kong.Parse(&CLI,
		kong.Name("yaraman"),
		kong.Description("Manage your YARA rules."),
		kong.Vars{
			"config_file": defaultConfigFile,
		},
		kong.UsageOnError(),
	)
	ctx := &YaramanContext{
		configFile:     CLI.ConfigFile,
		logLevel:       CLI.LogLevel,
		execDir:        execDir,
		fileExtensions: MapSet{},
		rulesDir:       makeFullPath(execDir, "rules"),
		databaseDir:    makeFullPath(execDir, "db"),
		logDir:         makeFullPath(execDir, "log"),
		exportDir:      makeFullPath(execDir, "export"),
		repoHosts:      MapSet{},
	}
	if CLI.Extensions != "" {
		for _, extension := range strings.Split(CLI.Extensions, ",") {
			ctx.fileExtensions.Add(extension)
		}
	}
	initialize(ctx)
	logger.Debug().Msgf("context: %v", ctx)
	kongContext.Run(ctx)
	//	if err != nil {
	//		logger.Fatal().AnErr("error", err).Msg("Fatal error, terminating")
	//	}
	//	kongContext.FatalIfErrorf(err)
}
