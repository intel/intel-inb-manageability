/*

*/

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// isDir checks if a path is a directory
func isDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	} else {
		return info.IsDir(), err
	}
}

// must will log a fatal error and exit if the error passed into it is not nil
func must(err error, operation string) {
	if err != nil {
		log.Fatalf("%s failed with %s\n", operation, err)
	}
}

// mustRunCmd will attempt to run a command and fail if there is an error
func mustRunCmd(cmd *exec.Cmd) {
	print("Running cmd " + strings.Join(cmd.Args, " ") + "\n")
	must(cmd.Run(), strings.Join(cmd.Args, " "))
}

// copyFile copies a source file to a destination file
func copyFile(sourceName, destinationName string) error {
	sourceFileStat, err := os.Stat(sourceName)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a file", sourceName)
	}

	source, err := os.Open(filepath.Clean(sourceName))
	if err != nil {
		return err
	}
	defer func() {
		if err := source.Close(); err != nil {
			log.Fatalf("error closing file: %s", err)
		}
	}()

	destination, err := os.Create(destinationName)
	if err != nil {
		return err
	}

	defer func() {
		if err := destination.Close(); err != nil {
			log.Fatalf("error closing file: %s", err)
		}
	}()
	_, err = io.Copy(destination, source)
	return err
}

// mkDirIfNotExist makes a directory if it doesn't exist; it will log and exit on error
func mkDirIfNotExist(path string, mode os.FileMode) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, mode)
		if err != nil {
			log.Fatalf("Unable to mkdir %s: %s", path, err)
		}
	}
}
