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

func writeUpdateStatusWithHandler(handler FileHandler, jsonHandler JSONHandler, status, metadata, errorDetails string) error {
	// Create the update status log file if it does not exist.
	if _, err := handler.Stat(updateStatusLog); os.IsNotExist(err) {
		file, err := handler.Create(updateStatusLog)
		if err != nil {
			log.Printf("Error creating update status log file: %v\n", err)
			return err
		}
		defer file.Close()
	}

	// Open the update status log file for writing and truncate it.
	file, err := handler.OpenFile(updateStatusLog, os.O_WRONLY|os.O_TRUNC, 0644)
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

	// Marshal the JSON structure to a string using the injected JSON handler.
	jsonData, err := jsonHandler.MarshalIndent(updateStatus, "", "  ")
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

// Wrapper function for backward compatibility
func writeUpdateStatus(status, metadata, errorDetails string) error {
	return writeUpdateStatusWithHandler(DefaultFileHandler{}, DefaultJSONHandler{}, status, metadata, errorDetails)
}
