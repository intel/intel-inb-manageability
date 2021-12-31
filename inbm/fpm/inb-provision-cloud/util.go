/*

*/

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
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

// promptSelect asks a question with multiple options and expects an answer from the user
func promptSelect(query string, options []string) string {
	var input string

	for {
		println()
		println(query)
		for i, option := range options {
			fmt.Printf("%d: %s\n", i+1, option)
		}
		println()
		_, err := fmt.Scanln(&input)
		if err != nil {
			log.Fatalf("Error while prompting for a choice")
		}

		i, err := strconv.Atoi(input)
		if err != nil || i < 1 || i > len(options) {
			println("Invalid option. ")
		} else {
			return options[i-1]
		}
	}
}

// promptString asks a question and reads a string response from the user
func promptString(query string) string {
	println()
	println(query)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	} else {
		log.Fatalf("Error while prompting for a string")
		return ""
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

// must will log a fatal error and exit if the error passed into it is not nil
func must(err error, operation string) {
	if err != nil {
		log.Fatalf("%s failed with %s\n", operation, err)
	}
}
