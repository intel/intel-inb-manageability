/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

import (
	"log"
	"os"
	"path/filepath"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
)

type Cleaner struct {
	commandExecutor utils.Executor
}

type CleanerInterface interface {
	DeleteAll(path string) error
}

func NewCleaner(commandExecutor utils.Executor) *Cleaner {
	return &Cleaner{
		commandExecutor: commandExecutor}
}

func (c *Cleaner) DeleteAll(path string) error {
	log.Println("Removes file after update")
	// Walk through the directory and remove all files
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		// Remove the file
		err = os.Remove(p)
		if err != nil {
			log.Printf("Failed to delete file: %s, error: %v\n", p, err)
		} else {
			log.Printf("Deleted file: %s\n", p)
		}
		return err
	})
	if err != nil {
		log.Printf("Failed to delete files in path %s: %v\n", path, err)
		return err
	}
	return nil
}
