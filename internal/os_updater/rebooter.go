/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// Rebooter is an interface that contains the method to reboot the OS.
type Rebooter interface {
	reboot() error
}

type rebooter struct {}

// Abstract reboot method
func (r *rebooter) reboot() error {
	return nil
}
