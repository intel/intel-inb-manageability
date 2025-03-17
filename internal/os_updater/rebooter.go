/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// Rebooter is an interface that contains the method to reboot the OS.
type Rebooter interface {
	Reboot() error
}

// OSRebooter is the struct to hold parameters to reboot the OS
type OSRebooter struct {}

// Reboot is an abstract method
func (r *OSRebooter) Reboot() error {
	return nil
}
