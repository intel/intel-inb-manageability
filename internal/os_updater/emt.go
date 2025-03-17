/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// EMTDownloader is the struct for parameters needed to download the OS for EMT.
type EMTDownloader struct{}

// Download implements IDownloader.
func (u *EMTDownloader) Download() error {	
	panic("unimplemented")
}

// EMTUpdater is the struct for parameters needed to update the OS for EMT.
type EMTUpdater struct{}

// Update updates the OS for EMT.
func (u *EMTUpdater) Update() error {
	panic("unimplemented")
}

// EMTRebooter is the struct for parameters needed to reboot the OS for EMT.
type EMTRebooter struct{}

// Reboot method for EMT
func (u *EMTRebooter) Reboot() error {
	panic("unimplemented")
}
