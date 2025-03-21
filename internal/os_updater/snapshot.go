/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package snapshot creates a snapshot prior to system update.

package osupdater

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
)

const (
	emtImageIDPath      = "/etc/image-id"
	dispatcherStatePath = "/var/intel-manageability/dispatcher_state"
)

// State represents the JSON structure
type EmtState struct {
	RestartReason string `json:"restart_reason"`
	TiberVersion  string `json:"tiber-version"`
}

// Snapshot creates a snapshot of the system.
func Snapshot() error {
	fmt.Println("Take a snapshot.")

	cmdExecutor := utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput)
	// Clear the dispatcher state file before writing it.
	// we use truncate rather than remove here as some OSes like Emt require files that need to persist
	// between reboots to not be removed.
	dispatcherStateTruncateCommand := []string{
		"sudo", "truncate", "-s", "0", dispatcherStatePath,
	}

	if _, err := cmdExecutor.Execute(dispatcherStateTruncateCommand); err != nil {
		return fmt.Errorf("failed to trancate dispatcher state file with command(%v)- %v", dispatcherStateTruncateCommand, err)
	}

	os, err := DetectOS()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to detect OS: %v", err)
		return fmt.Errorf(errMsg)
	}

	if os == "EMT" {
		buildDate, err := getImageBuildDate()
		if err != nil || buildDate == "" {
			return fmt.Errorf("failed to get image build date: %v", err)
		}
		// Create an instance of EmtState with the desired values
		state := EmtState{
			RestartReason: "sota",
			TiberVersion:  buildDate,
		}
		// Convert the state to JSON
		jsonData, err := json.Marshal(state)
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return fmt.Errorf("error marshalling JSON: %v", err)
		}

		// Write the JSON to the dispatcher state file
		if err := writeToDispatcherStateFile(string(jsonData)); err != nil {
			return fmt.Errorf("failed to write to dispatcher state file: %v", err)
		}

	}

	if os == "Ubuntu" {
		panic("Not implemented")
	}

	return nil
}

// Get the image build date.
func getImageBuildDate() (string, error) {
	// Open the file
	file, err := os.Open(emtImageIDPath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Iterate through each line
	for scanner.Scan() {
		line := scanner.Text()

		// Check if the line contains IMAGE_BUILD_DATE
		if strings.HasPrefix(line, "IMAGE_BUILD_DATE=") {
			// Extract the value after the '=' sign
			imageBuildDate := strings.Split(line, "=")[1]
			fmt.Println("IMAGE_BUILD_DATE:", imageBuildDate)
			return imageBuildDate, nil
		}
	}

	fmt.Println("IMAGE_BUILD_DATE not found.")
	return "", nil
}

func writeToDispatcherStateFile(content string) error {
	// Open the file
	file, err := os.Open(dispatcherStatePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return err
	}
	defer file.Close()

	// Write the content to the file
	_, err = file.WriteString(content)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}
