/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"encoding/json"
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

type FileHandler interface {
	Stat(name string) (os.FileInfo, error)
	Create(name string) (FileWriter, error)
	OpenFile(name string, flag int, perm os.FileMode) (FileWriter, error)
}

type DefaultFileHandler struct{}

func (o DefaultFileHandler) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (o DefaultFileHandler) Create(name string) (FileWriter, error) {
	file, err := os.Create(name)
	var writer FileWriter = file
	return writer, err
}

func (o DefaultFileHandler) OpenFile(name string, flag int, perm os.FileMode) (FileWriter, error) {
	file, err := os.OpenFile(name, flag, perm)
	var writer FileWriter = file
	return writer, err
}

type JSONHandler interface {
	MarshalIndent(v interface{}, prefix, indent string) ([]byte, error)
}

type DefaultJSONHandler struct{}

func (d DefaultJSONHandler) MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

type FileWriter interface {
	Write(p []byte) (int, error)
	Close() error
}

func writeUpdateStatusWithHandler(handler FileHandler, jsonHandler JSONHandler, status, metadata, errorDetails string) {
	// Create the update status log file if it does not exist.
	if _, err := handler.Stat(updateStatusLogPath); os.IsNotExist(err) {
		file, err := handler.Create(updateStatusLogPath)
		if err != nil {
			log.Printf("[Warning] Error writing update status: failed to create update status log file: %v", err)
		}
		defer file.Close()
	}

	// Open the update status log file for writing and truncate it.
	file, err := handler.OpenFile(updateStatusLogPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("[Warning] Error writing update status: failed to open update status log file: %v", err)
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

	// Marshal the JSON structure to a string using the injected JSON handler.
	jsonData, err := jsonHandler.MarshalIndent(updateStatus, "", "  ")
	if err != nil {
		log.Printf("[Warning] Error writing update status: failed to marshal JSON: %v", err)
	}

	// Write the JSON data to the file.
	_, err = file.Write(jsonData)
	if err != nil {
		log.Printf("[Warning] Error writing update status log file: %v", err)
	}
}

func writeGranularLog(statusDetail string, failureReason string) {
	// Create the granular log file if it does not exist.
	if _, err := os.Stat(granularLogPath); os.IsNotExist(err) {
		file, err := os.Create(granularLogPath)
		if err != nil {
			log.Printf("[Warning] Error writing granular log: failed to create granular log file: %v", err)
		}
		defer file.Close()
	}

	// Open the granular log file for writing and truncate it.
	file, err := os.OpenFile(granularLogPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("[Warning] Error writing granular log: failed to open granular log file: %v", err)
	}
	defer file.Close()

	// If update is successful, get the image build date and write it to the granular log.
	// If update is not successful, write the failure reason to the granular log.
	var granularLogData map[string][]map[string]string
	if statusDetail == SUCCESS {
		buildDate, err := GetImageBuildDate()
		if err != nil || buildDate == "" {
			log.Printf("[Warning] Error writing granular log: failed to get image build date: %v", err)
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
		log.Printf("[Warning] Error writing granular log: failed to marshal JSON for granular log: %v", err)
	}

	// Write the JSON data to the file.
	_, err = file.Write(jsonData)
	if err != nil {
		log.Printf("[Warning] Error writing granular log: failed to write to granular log file: %v", err)
	}
}

// Wrapper function for backward compatibility
func writeUpdateStatus(status, metadata, errorDetails string) {
	writeUpdateStatusWithHandler(DefaultFileHandler{}, DefaultJSONHandler{}, status, metadata, errorDetails)
}
