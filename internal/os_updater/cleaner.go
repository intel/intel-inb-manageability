/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cleaner helps to remove the file or directory.
package osupdater

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

func NewCleaner(commandExecutor utils.Executor, osType string) *Cleaner {
	return &Cleaner{
		commandExecutor: commandExecutor}
}

func (c *Cleaner) DeleteAll(path string) error {
	log.Println("Removes file after update")
	// Walk through the directory and remove all files and subdirectories
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Remove the file or directory
		if info.IsDir() {
			return os.RemoveAll(p)
		}
		return os.Remove(p)
	})
	if err != nil {
		log.Printf("Failed to delete files in path %s: %v\n", path, err)
		return err
	}
	log.Printf("Successfully deleted all files in path %s\n", path)
	return nil
}
