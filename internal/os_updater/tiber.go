/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// TiberDownloader is the concrete implementation of the IDownloader interface
// for the Tiber OS.
type TiberDownloader struct{}

// download implements IDownloader.
func (t *TiberDownloader) download() error {	
	panic("unimplemented")
}

// TiberUpdater is the concrete implementation of the IUpdater interface
// for the Tiber OS.
type TiberUpdater struct{}

// Update method for Tiber
func (tu *TiberUpdater) update() error {
	panic("unimplemented")
}

// TiberRebooter is the concrete implementation of the IUpdater interface
// for the Tiber OS.
type TiberRebooter struct{}

// Reboot method for Tiber
func (tu *TiberRebooter) reboot() error {
	panic("unimplemented")
}
