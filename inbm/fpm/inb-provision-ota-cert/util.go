/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
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

// promptYesNo asks a question and expects a yes or no answer from the user
func promptYesNo(query string) bool {
	for {
		print(query + " [Y/N] ")
		input := ""
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			input = scanner.Text()
		} else {
			log.Fatalf("Error while prompting for a yes or no")
		}

		normalizedInput := strings.ToLower(strings.TrimSpace(input))

		if normalizedInput == "y" || normalizedInput == "yes" {
			return true
		} else if normalizedInput == "n" || normalizedInput == "no" {
			return false
		} else {
			println("Input not recognized.")
		}
	}
}

// promptFile asks for a filename to read data from, from the user
func promptFile(query string) []byte {
	println()

	for {
		println("Please enter a filename to import " + query + ":")
		fileName := ""
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			fileName = scanner.Text()
		} else {
			log.Fatalf("Error while prompting for a filename")
		}
		if fileExists(fileName) {
			content, err := ioutil.ReadFile(fileName)
			if err != nil {
				log.Fatalf("Error while reading file " + fileName)
			}
			return content
		} else {
			println("File " + fileName + " not found.")
		}
	}
}

func readMultilineString() string {
	println("(press [ENTER] on a blank line when finished)")
	scanner := bufio.NewScanner(os.Stdin)
	result := ""
	for {
		if scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				return result
			}
			result = result + line + "\n"
		} else {
			log.Fatalf("Error while reading a line from standard input")
		}
	}
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		log.Fatalf("Error querying %s", filename)
	}
	return !info.IsDir()
}
