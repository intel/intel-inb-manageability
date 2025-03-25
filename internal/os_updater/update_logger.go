/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package update_logger creates and updates the update status log and granular log.

package osupdater

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

var (
	updateStatusLog = "/var/log/inbm-update-status.log"
)

type UpdateStatus struct {
	Status   string `json:"Status"`
	Type     string `json:"Type"`
	Time     string `json:"Time"`
	Metadata string `json:"Metadata"`
	Error    string `json:"Error"`
	Version  string `json:"Version"`
}

func writeUpdateStatus(status, metadata, errorDetails string) error {
	// Create the update status log file if it does not exist.
	if _, err := os.Stat(updateStatusLog); os.IsNotExist(err) {
		file, err := os.Create(updateStatusLog)
		if err != nil {
			log.Printf("Error creating update status log file: %v\n", err)
			return err
		}
		defer file.Close()
	}

	// Open the update status log file for writing and truncate it.
	file, err := os.OpenFile(updateStatusLog, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Error opening update status log file: %v\n", err)
		return err
	}
	defer file.Close()

	// Create the JSON structure.
	updateStatus := UpdateStatus{
		Status:   status,
		Type:     "sota",
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Metadata: metadata,
		Error:    errorDetails,
		Version:  "v1",
	}

	// Marshal the JSON structure to a string.
	jsonData, err := json.MarshalIndent(updateStatus, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	// Write the JSON data to the file.
	_, err = file.Write(jsonData)
	if err != nil {
		log.Printf("Error writing to update status log file: %v\n", err)
		return err
	}
	return nil
}
