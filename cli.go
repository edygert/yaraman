package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// DirCmd holds CLI values for directory processing
type DirCmd struct {
	Name    string `required short:"n" help:"Name of the import directory from which to import YARA rules."`
	Subdirs bool   `short:"s" help:"Set to true to process all subdirectories (default false)" default:"false"`
}

// GithubCmd holds CLI values for github processing
type GithubCmd struct {
	Repo string `short:"r" required help:"Name of the github repository to import."`
}

// FileCmd holds CLI values for file processing
type FileCmd struct {
	Name string `short:"n" required help:"Filename containing rule(s) to import."`
}

// ImportCmd holds CLI values for importing YARA rules.
type ImportCmd struct {
	Dir    DirCmd    `cmd help:"Import YARA rules from a directory."`
	Github GithubCmd `cmd help:"Import YARA rules from a github repository."`
	File   FileCmd   `cmd help:"Import YARA rules from a file."`
}

// ValuesCmd holds CLI values for listing values of a searchable field.
type ValuesCmd struct {
	Field string `required short:"f" help:"Name of field whose values are to be listed."`
}

// FieldsCmd is an empty struct to use for creating a Run method
type FieldsCmd struct{}

// ListCmd holds CLI values for listing fields/values
type ListCmd struct {
	Fields FieldsCmd `cmd help:"List searchable fields."`
	Values ValuesCmd `cmd help:"List values for a searchable field."`
}

// ExportCmd holds CLI values for exporting YARA rules.
type ExportCmd struct {
}

// SearchCmd holds CLI values for searching for YARA rules.
type SearchCmd struct {
}

// CLI is the master structure for all CLI commands.
var CLI struct {
	ConfigFile string    `short:"c"`
	Import     ImportCmd `cmd help:"Import YARA rules."`
	List       ListCmd   `cmd help:"List searchable fields or values of a field."`
	Export     ExportCmd `cmd help:"Export YARA rules that match the specified criteria, or all rules if no criteria are specified."`
	Search     ExportCmd `cmd help:"Search YARA rules using the specified query criteria."`
}

func yaraFileFunc(filename string) error {
	isYaraFile, _ := filepath.Match(`*.yar*`, strings.ToLower(filepath.Base(filename)))
	if !isYaraFile {
		return nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseRuleset(f, makeYaraDoc)
}

// Run executes the DirCmd. Import yara rules from a directory and optionally all subdirectories.
func (cmd *DirCmd) Run(ctx *Context) error {
	if !dirExists(cmd.Name) {
		return fmt.Errorf("directory %s does not exist", cmd.Name)
	}
	return findFiles(cmd.Name, cmd.Subdirs, yaraFileFunc)
}

// Run imports yara rules from a specific file
func (cmd *FileCmd) Run(ctx *Context) error {
	if cmd.Name == "stdin" || cmd.Name == "-" {
		return parseRuleset(os.Stdin, makeYaraDoc)
	}

	if !fileExists(cmd.Name) {
		return fmt.Errorf("file %s does not exist", cmd.Name)
	}
	err := yaraFileFunc(cmd.Name)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	return nil
}

// Import yara rules from github repo by downloading the repo and
// recursively iterating over all directories.
func (cmd *GithubCmd) run(ctx *Context) error {
	// get the repo then run findFiles on the destination directory
	// return findFiles(cmd.Name, true, yaraFileFunc)
	log.Printf("File: %s", cmd.Repo)
	return nil
}
