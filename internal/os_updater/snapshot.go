/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

const (
	SUCCESS = "SUCCESS"
	FAIL    = "FAIL"
)

var (
	emtImageIDPath      = "/etc/image-id"
	dispatcherStatePath = "/var/intel-manageability/dispatcher_state"
)


// EMTState represents the JSON structure
type EMTState struct {
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
		return fmt.Errorf("failed to truncate dispatcher state file with command(%v)- %w", dispatcherStateTruncateCommand, err)
	}

	os, err := DetectOS()
	if err != nil {
		return fmt.Errorf("failed to detect OS: %w", err)
	}

	if os == "EMT" {
		buildDate, err := GetImageBuildDate()
		if err != nil || buildDate == "" {
			return fmt.Errorf("failed to get image build date: %w", err)
		}
		// Create an instance of EmtState with the desired values
		state := EMTState{
			RestartReason: "sota",
			TiberVersion:  buildDate,
		}
		// Convert the state to JSON
		jsonData, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("error marshalling JSON: %w", err)
		}

		// Write the JSON to the dispatcher state file
		if err := writeToDispatcherStateFile(string(jsonData)); err != nil {
			return fmt.Errorf("failed to write to dispatcher state file: %w", err)
		}

	}

	if os == "Ubuntu" {
		panic("Not implemented")
	}

	return nil
}

// GetImageBuildDate get the image build date.
func GetImageBuildDate() (string, error) {
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

// writeToDispatcherStateFile writes the content to the dispatcher state file.
func writeToDispatcherStateFile(content string) error {
	// Open the file
	file, err := os.OpenFile(dispatcherStatePath, os.O_WRONLY|os.O_CREATE, 0644)
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

// ReadDispatcherStateFile reads the content from the dispatcher state file.
// It returns the image version.
func ReadDispatcherStateFile(osType string) (string, error) {

	if osType == "EMT" {
		file, err := os.Open(dispatcherStatePath)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return "", err
		}
		defer file.Close()

		// Read the file content
		fileContent, err := os.ReadFile(dispatcherStatePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return "", err
		}

		// Parse the JSON content
		var state EMTState
		err = json.Unmarshal(fileContent, &state)
		if err != nil {
			fmt.Println("Error parsing JSON:", err)
			return "", err
		}
		return state.TiberVersion, nil
	}

	return "", fmt.Errorf("OS not supported")
}

func VerifyUpdateAfterReboot(osType string) error {

	// Check if dispatcher state file exist.
	if _, err := os.Stat(dispatcherStatePath); err == nil {
		fmt.Println("Perform post update verification.")
		if osType == "EMT" {
			previousVersion, err := ReadDispatcherStateFile(osType)
			if err != nil {
				return fmt.Errorf("error reading dispatcher state file: %w", err)
			}

			currentVersion, err := GetImageBuildDate()
			if err != nil {
				return fmt.Errorf("error getting image build date: %w", err)
			}

			// Compare the versions
			if currentVersion != previousVersion {
				fmt.Printf("Update Success. Previous image: %v, Current image: %v", previousVersion, currentVersion)
			} else {
				fmt.Println("Update failed. Reverting to previous image.")
				// Write the status to the log file.
				err := writeUpdateStatus(FAIL, "", "Update failed. Version are same.")
				if err != nil {
					fmt.Printf("[Warning] Error writing update status: %v", err)
				}
				fmt.Println("Rebooting...")
				// Reboot the system without commit.
				// //TODO: Only reboot here? Or should we also reboot without commit in other failure?
				emtRebooter := NewEMTRebooter(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), &pb.UpdateSystemSoftwareRequest{})
				err = emtRebooter.Reboot()
				if err != nil {
					return fmt.Errorf("error rebooting system: %w", err)
				}
			}

			emtUpdater := NewEMTUpdater(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), &pb.UpdateSystemSoftwareRequest{})
			err = emtUpdater.commitUpdate()
			if err != nil {
				return fmt.Errorf("error committing update: %w", err)
			}

			// Write status to the log file.
			err = writeUpdateStatus(SUCCESS, "", "SUCCESSFUL INSTALL: Overall SOTA update successful.  System has been properly updated.")
			if err != nil {
				fmt.Printf("[Warning] Error writing update status: %v", err)
			}

			// TODO: Write the granular log for success and fail cases.

		}

	} else {
		fmt.Println("No dispatcher state file. Skip post update verification.")
	}

	return nil
}
