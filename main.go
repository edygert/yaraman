package main

import (
	"fmt"
	"os"
	"path"

	"github.com/alecthomas/kong"
	toml "github.com/pelletier/go-toml"
)

// Context provides context for CLI handling
type Context struct {
	configFile       string
	databaseDir      string // where bleve files are stored (and bbolt db files if used)
	gitBaseDir       string // where git rules are downloaded to
	defaultExportDir string // where exported rules are stored by default
}

var (
	execDir    string
	configFile string
)

var yaraKeywords = []string{
	"all",
	"and",
	"any",
	"ascii",
	"at",
	"base64",
	"base64wide",
	"condition",
	"contains",
	"entrypoint",
	"false",
	"filesize",
	"for",
	"fullword",
	"global",
	"import",
	"in",
	"include",
	"int16",
	"int16be",
	"int32",
	"int32be",
	"int8",
	"int8be",
	"matches",
	"meta",
	"nocase",
	"not",
	"of",
	"or",
	"private",
	"rule",
	"strings",
	"them",
	"true",
	"uint16",
	"uint16be",
	"uint32",
	"uint32be",
	"uint8",
	"uint8be",
	"wide",
	"xor",
}

func bleve() {
	// open a new index
	/*
		mapping := bleve.NewIndexMapping()
		index, err := bleve.New("example.bleve", mapping)
		if err != nil {
			fmt.Println(err)
			return
		}

		data := struct {
			Name string
		}{
			Name: "text",
		}

		// index some data
		index.Index("id", data)

		// search for some text
		query := bleve.NewMatchQuery("text")
		search := bleve.NewSearchRequest(query)
		searchResults, err := index.Search(search)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(searchResults)
	*/
}

func initialize(configFile string, ctx *Context) error {
	if !fileExists(configFile) {
		return fmt.Errorf("Configuration file %s does not exist", configFile)
	}

	config, _ := toml.LoadFile(configFile)
	ctx.databaseDir = config.Get("yaraman.database_dir").(string)
	ctx.gitBaseDir = config.Get("yaraman.github_dir").(string)
	ctx.defaultExportDir = config.Get("yaraman.default_export_dir").(string)

	return nil
}

func main() {
	execDir, _ = os.Executable()
	execDir = path.Dir(execDir)
	configFile = execDir + "/yaraman.toml"

	ctx := &Context{configFile: configFile}

	kongContext := kong.Parse(&CLI)
	err := kongContext.Run(ctx)
	kongContext.FatalIfErrorf(err)
}
