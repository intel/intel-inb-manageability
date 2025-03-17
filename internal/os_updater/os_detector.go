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
)

// OSType represents the type of OS.
type OSType int

const (
	// linux represents the Linux OS.
	linux OSType = iota
	// UnsupportedOS represents an unsupported OS.
	unsupportedOS
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
	cmd := exec.Command("lsb_release", "-a")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	output = bytes.ReplaceAll(output, []byte("\n"), []byte(""))

	switch {
	case bytes.Contains(output, []byte("Ubuntu")):
		return "Ubuntu", nil
	case bytes.Contains(output, []byte("microvisor")):
		return "EMT", nil
	}

	return string(output), nil
}

func getOSType() OSType {
	os := runtime.GOOS

	switch os {
	case "linux":
		return linux
	default:
		return unsupportedOS
	}
}
