/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/intel/intel-inb-manageability/internal/logger"
)

// OSType represents the type of OS.
type OSType int

const (
	// linux represents the Linux OS.
	linux OSType = iota
	// UnsupportedOS represents an unsupported OS.
	unsupportedOS
)

// CommandRunner is a function type that runs a command and returns its combined output.
type CommandRunner func(name string, arg ...string) ([]byte, error)

// OSGetter is a function type that returns the OS type.
type OSGetter func() string

var (
	execCommand CommandRunner = func(name string, arg ...string) ([]byte, error) {
		cmd := exec.Command(name, arg...)
		return cmd.CombinedOutput()
	}
	getOS OSGetter = func() string { return runtime.GOOS }
)

// DetectOS detects the OS.
func DetectOS() (string, error) {
	osType := getOSType()

	if osType == linux {
		return detectLinuxDistribution()
	}
	return "", fmt.Errorf("unsupported OS type detected")
}

func detectLinuxDistribution() (string, error) {
	output, err := execCommand("lsb_release", "-a")
	if err != nil {
		return "", err
	}
	output = bytes.ReplaceAll(output, []byte("\n"), []byte(""))

	switch {
	case bytes.Contains(output, []byte("Ubuntu")):
		logger.Debug("Detected Ubuntu OS")
		return "Ubuntu", nil
	case bytes.Contains(output, []byte("microvisor")):
		logger.Debug("Detected EMT OS")
		return "EMT", nil
	default:
		return "", fmt.Errorf("unsupported Linux distribution detected")
	}
}

func getOSType() OSType {
	os := getOS()

	switch os {
	case "linux":
		logger.Debug("Detected Linux OS")
		return linux
	default:
		logger.Error("Unsupported OS type detected")
		return unsupportedOS
	}
}
