package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type fileCallbackType func(ctx *Context, filename string) error

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.Mode().IsRegular()
}

func dirExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func findFiles(ctx *Context, parent string, recursive bool, callback fileCallbackType) error {
	parent = filepath.Clean(parent)
	pathExists := dirExists(parent)
	if !pathExists {
		return fmt.Errorf("directory %s does not exist", parent)
	}

	if recursive {
		err := filepath.Walk(parent, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}

			err = callback(ctx, path)
			if err != nil {
				errorLogger.Error().AnErr("error", err).Str("filename", path).Msg("Error processing file")
			}
			return nil
		})
		return err
	}

	files, err := ioutil.ReadDir(parent)
	if err != nil {
		return err
	}

	for _, fileInfo := range files {
		err := callback(ctx, parent+string(os.PathListSeparator)+fileInfo.Name())
		if err != nil {
			return err
		}
	}
	return nil
}
