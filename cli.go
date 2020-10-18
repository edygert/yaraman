package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"
)

// ImportCmd holds CLI values for importing YARA rules.
type ImportCmd struct {
	Dir     string `short:"d" xor:"import" help:"Import YARA rules from a directory."`
	Github  string `short:"g" xor:"import" help:"Import YARA rules from a github repository."`
	File    string `short:"f" xor:"import" help:"Import YARA rules from a file."`
	URL     string `short:"u" xor:"import" help:"Import YARA rules from a file on the internet."`
	Subdirs bool   `short:"s" default:"false" help:"Specify this to process all subdirectories. Only applies to importing from directories."`
}

// ValuesCmd holds CLI values for listing values of a searchable field.
type ValuesCmd struct {
	Field string `required:"true" short:"f" help:"Name of field whose values are to be listed."`
}

// FieldsCmd is an empty struct to use for creating a Run method
type FieldsCmd struct{}

// ListCmd holds CLI values for listing fields/values
type ListCmd struct {
	Fields FieldsCmd `cmd:"" help:"List searchable fields."`
	Values ValuesCmd `cmd:"" help:"List values for a searchable field."`
}

// ExportCmd holds CLI values for exporting YARA rules.
type ExportCmd struct {
	Format string `short:"f" default:"yara" enum:"json,yara" help:"Format of the exported data (yara or json)."`
}

// SearchCmd holds CLI values for searching for YARA rules.
type SearchCmd struct {
}

// InteractiveCmd is the placeholder for interactive mode
type InteractiveCmd struct {
}

// VersionCmd is for running the version command
type VersionCmd struct {
}

// CLI is the master structure for all CLI commands.
var CLI struct {
	ConfigFile  string         `short:"c" default:"${config_file}"`
	LogLevel    string         `short:"l" default:"normal" enum:"normal,debug" help:"Desired level of logging (normal, debug)"`
	Extensions  string         `short:"e" help:"Comma separated list of file extensions of yara rules (default yara,yar)"`
	Version     VersionCmd     `cmd:"" help:"Show program version."`
	Import      ImportCmd      `cmd:"" help:"Import YARA rules."`
	List        ListCmd        `cmd:"" help:"List searchable fields or values of a field."`
	Export      ExportCmd      `cmd:"" help:"Export YARA rules that match the specified criteria, or all rules if no criteria are specified."`
	Search      ExportCmd      `cmd:"" help:"Search YARA rules using the specified query criteria."`
	Interactive InteractiveCmd `cmd:"" help:"Enter interactive mode."`
}

func yaraFileFunc(ctx *Context, filename string) error {
	found := false
	for extension := range ctx.fileExtensions {
		found, _ = filepath.Match(`*.`+extension, strings.ToLower(filepath.Base(filename)))
		if found {
			break
		}
	}
	if !found {
		return nil
	}
	return parseRulesetFile(filename, makeYaraDoc)
}

// Run executes the VersionCmd.
func (cmd *VersionCmd) Run(ctx *Context) error {
	fmt.Println("yaraman Version 0.1")
	return nil
}

// Run executes the ImportCmd to import YARA rules from various sources.
func (cmd *ImportCmd) Run(ctx *Context) error {
	switch {
	case cmd.Dir != "":
		logger.Info().Msg("Importing directory")
		if !dirExists(cmd.Dir) {
			return fmt.Errorf("directory %s does not exist", cmd.Dir)
		}
		return findFiles(ctx, cmd.Dir, cmd.Subdirs, yaraFileFunc)

	case cmd.File != "":
		logger.Info().Str("filename", cmd.File).Msg("Importing file")
		if !fileExists(cmd.File) {
			errorLogger.Error().Str("filename", cmd.File).Msg("File does not exist.")
			return nil
		}
		err := yaraFileFunc(ctx, cmd.File)
		if err != nil {
			errorLogger.Error().Str("filename", cmd.File).Msg("Error processing file.")
		}

	case cmd.URL != "":
		resp, err := http.Get(cmd.URL)
		if err != nil {
			errorLogger.Error().AnErr("error", err).Str("url", cmd.URL).Msg("error reading YARA from web")
			return nil
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errorLogger.Error().AnErr("error", err).Str("url", cmd.URL).Msg("error reading data from web page")
			return nil
		}
		err = ioutil.WriteFile("test.yara", data, 0644)
		if err != nil {
			errorLogger.Error().AnErr("error", err).Str("url", cmd.URL).Msg("error writing web page to disk")
			return nil
		}
		err = yaraFileFunc(ctx, "test.yara")
		if err != nil {
			errorLogger.Error().AnErr("error", err).Str("filename", "test.yara").Msg("error parsing yara file")
			return nil
		}

	case cmd.Github != "":
		logger.Info().Str("repository", cmd.Github).Msg("Import from github")
	}
	return nil
}

// Run starts yaraman in interactive mode.
func (cmd *InteractiveCmd) Run(ctx *Context) error {
	box := tview.NewBox().SetBorder(true).SetTitle("Hello, world!")
	if err := tview.NewApplication().SetRoot(box, true).Run(); err != nil {
		errorLogger.Error().AnErr("error", err).Msg("Error from tview.Run")
	}
	return nil
}
