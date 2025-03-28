/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package update_logger creates and updates the update status log and granular log.

package osupdater

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	FAILURE_REASON_UNSPECIFIED          = "unspecified"
	FAILURE_REASON_DOWNLOAD             = "download"
	FAILURE_REASON_INSUFFICIENT_STORAGE = "insufficientstorage"
	FAILURE_REASON_RS_AUTHENTICATION    = "rsauthentication"
	FAILURE_REASON_SIGNATURE_CHECK      = "signaturecheck"
	FAILURE_REASON_UT_WRITE             = "utwrite"
	FAILURE_REASON_BOOT_CONFIGURATION   = "utbootconfiguration"
	FAILURE_REASON_BOOTLOADER           = "bootloader"
	FAILURE_REASON_CRITICAL_SERVICES    = "criticalservices"
	FAILURE_REASON_INBM                 = "inbm"
	FAILURE_REASON_OS_COMMIT            = "oscommit"
)

var (
	updateStatusLogPath = "/var/log/inbm-update-status.log"
	granularLogPath     = "/var/log/inbm-update-log.log"
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
	if _, err := os.Stat(updateStatusLogPath); os.IsNotExist(err) {
		file, err := os.Create(updateStatusLogPath)
		if err != nil {
			log.Printf("Error creating update status log file: %v\n", err)
			return err
		}
		defer file.Close()
	}

	// Open the update status log file for writing and truncate it.
	file, err := os.OpenFile(updateStatusLogPath, os.O_WRONLY|os.O_TRUNC, 0644)
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

func writeGranularLog(statusDetail string, failureReason string) error {
	// Create the granular log file if it does not exist.
	if _, err := os.Stat(granularLogPath); os.IsNotExist(err) {
		file, err := os.Create(granularLogPath)
		if err != nil {
			log.Printf("Error creating granular log file: %v\n", err)
			return err
		}
		defer file.Close()
	}

	// Open the granular log file for writing and truncate it.
	file, err := os.OpenFile(granularLogPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Error opening granular log file: %v\n", err)
		return err
	}
	defer file.Close()

	// If update is successful, get the image build date and write it to the granular log.
	// If update is not successful, write the failure reason to the granular log.
	granularLogData := map[string][]map[string]string{}
	if statusDetail == SUCCESS {
		buildDate, err := GetImageBuildDate()
		if err != nil || buildDate == "" {
			log.Printf("Failed to get image build date: %v\n", err)
			return fmt.Errorf("failed to get image build date: %w", err)
		}
		granularLogData = map[string][]map[string]string{
			"UpdateLog": {
				{
					"StatusDetail.Status": statusDetail,
					"Version":             buildDate,
				},
			},
		}
	} else {
		// Create the JSON structure.
		granularLogData = map[string][]map[string]string{
			"UpdateLog": {
				{
					"StatusDetail.Status": statusDetail,
					"FailureReason":       failureReason,
				},
			},
		}
	}

	// Marshal the JSON structure to a string.
	jsonData, err := json.MarshalIndent(granularLogData, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON for granular log: %v\n", err)
		return err
	}

	// Write the JSON data to the file.
	_, err = file.Write(jsonData)
	if err != nil {
		log.Printf("Error writing to granular log file: %v\n", err)
		return err
	}
	return nil
}
