/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */

// Package osupdater updates the OS.
package osupdater

// IRebooter is an interface that contains the method to reboot the OS.
type IRebooter interface {
	reboot() error
}

type rebooter struct {}

// Abstract reboot method
func (r *rebooter) reboot() error {
	return nil
}
