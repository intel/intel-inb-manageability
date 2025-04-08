/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

var (
	// OsUpdateTool will be changed in 3.1 release. Have to change the name and API call.
	// Check https://github.com/intel-sandbox/os.linux.tiberos.ab-update.go/blob/main/README.md
	osUpdateToolPath = "/usr/bin/os-update-tool.sh"
)

// EMTUpdater is the concrete implementation of the IUpdater interface
// for the EMT OS.
type EMTUpdater struct {
	commandExecutor   utils.Executor
	request           *pb.UpdateSystemSoftwareRequest
	writeUpdateStatus func(string, string, string)
	writeGranularLog  func(string, string)
}

// NewEMTUpdater creates a new EMTUpdater.
func NewEMTUpdater(commandExecutor utils.Executor, request *pb.UpdateSystemSoftwareRequest) *EMTUpdater {
	return &EMTUpdater{
		commandExecutor:   commandExecutor,
		request:           request,
		writeUpdateStatus: writeUpdateStatus,
		writeGranularLog:  writeGranularLog,
	}
}

// errReader is a helper type to simulate an error during reading
type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("error copying response body")
}

// Update method for Emt
func (t *EMTUpdater) Update() (bool, error) {
	// Print the value of tu.request.Mode
	log.Printf("Mode: %v\n", t.request.Mode)

	// Get the request details
	jsonString, err := protojson.Marshal(t.request)
	if err != nil {
		log.Printf("Error converting request to string: %v\n", err)
		jsonString = []byte("{}")
	}

	if t.request.Mode == pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY {

		err := t.VerifyHash()
		if err != nil {
			t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
			t.writeGranularLog(FAIL, FAILURE_REASON_SIGNATURE_CHECK)
			return false, fmt.Errorf("hash verification failed: %w", err)
		}

		log.Println("Execute update tool write command.")

		// Extract the file name from the URL
		urlParts := strings.Split(t.request.Url, "/")
		fileName := urlParts[len(urlParts)-1]

		// Create the file
		filePath := DownloadDir + "/" + fileName

		updateToolWriteCommand := []string{
			"sudo", osUpdateToolPath, "-w", "-u", filePath, "-s", t.request.Signature,
		}

		if _, _, err := t.commandExecutor.Execute(updateToolWriteCommand); err != nil {
			t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
			t.writeGranularLog(FAIL, FAILURE_REASON_UT_WRITE)
			return false, fmt.Errorf("failed to execute shell command(%v)- %v", updateToolWriteCommand, err)
		}

		jsonString, err := protojson.Marshal(t.request)
		if err != nil {
			log.Printf("Error converting request to string: %v\n", err)
			jsonString = []byte("{}")
		}
		// Write the update status to the status log file
		t.writeUpdateStatus(SUCCESS, string(jsonString), "")
	}

	if t.request.Mode == pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD {
		log.Println("Save snapshot before applying the update.")
		if err := Snapshot(); err != nil {
			errMsg := fmt.Sprintf("Error taking snapshot: %v", err)
			t.writeUpdateStatus(FAIL, string(jsonString), errMsg)
			t.writeGranularLog(FAIL, FAILURE_REASON_INBM)
			return false, fmt.Errorf("failed to take snapshot before applying the update: %v", err)
		}

		log.Println("Execute update tool apply command.")
		updateToolApplyCommand := []string{
			"sudo", osUpdateToolPath, "-a",
		}

		if _, _, err := t.commandExecutor.Execute(updateToolApplyCommand); err != nil {
			t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
			t.writeGranularLog(FAIL, FAILURE_REASON_BOOT_CONFIGURATION)
			return false, fmt.Errorf("failed to execute shell command(%v)- %v", updateToolApplyCommand, err)
		}

		// Write the update status to the status log file
		writeUpdateStatus(SUCCESS, string(jsonString), "")
		writeGranularLog(SUCCESS, "")
	}

	return true, nil
}

func (t *EMTUpdater) commitUpdate() error {
	log.Println("Committing the update.")
	// Get the request details
	jsonString, err := protojson.Marshal(t.request)
	if err != nil {
		log.Printf("Error converting request to string: %v\n", err)
		jsonString = []byte("{}")
	}

	updateToolCommitCommand := []string{
		osUpdateToolPath, "-c",
	}

	if _, _, err := t.commandExecutor.Execute(updateToolCommitCommand); err != nil {
		log.Printf("Error executing shell command(%v): %v\n", updateToolCommitCommand, err)
		t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
		t.writeGranularLog(FAIL, FAILURE_REASON_OS_COMMIT)
		return fmt.Errorf("failed to execute shell command(%v)- %v", updateToolCommitCommand, err)
	}
	return nil
}
