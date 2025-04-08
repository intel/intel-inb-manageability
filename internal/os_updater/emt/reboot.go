/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

import (
	"fmt"
	"log"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// EMTRebooter is the concrete implementation of the IUpdater interface
// for the EMT OS.
type EMTRebooter struct {
	commandExecutor   utils.Executor
	request           *pb.UpdateSystemSoftwareRequest
	writeUpdateStatus func(string, string, string)
	writeGranularLog  func(string, string)
}

// NewEMTRebooter creates a new EMTRebooter.
func NewEMTRebooter(commandExecutor utils.Executor, request *pb.UpdateSystemSoftwareRequest) *EMTRebooter {
	return &EMTRebooter{
		commandExecutor:   commandExecutor,
		request:           request,
		writeUpdateStatus: writeUpdateStatus,
		writeGranularLog:  writeGranularLog,
	}
}

// Reboot method for EMT
func (t *EMTRebooter) Reboot() error {
	log.Println("Rebooting the system...")
	// Get the request details
	jsonString, err := protojson.Marshal(t.request)
	if err != nil {
		log.Printf("Error converting request to string: %v\n", err)
		jsonString = []byte("{}")
	}

	rebootCommand := []string{
		"sudo", "/usr/sbin/reboot",
	}

	if _, _, err := t.commandExecutor.Execute(rebootCommand); err != nil {
		t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
		t.writeGranularLog(FAIL, FAILURE_REASON_UNSPECIFIED)
		return fmt.Errorf("failed to execute shell command(%v)- %v", rebootCommand, err)
	}
	return nil
}