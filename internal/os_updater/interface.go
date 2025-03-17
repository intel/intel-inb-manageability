/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import "fmt"

// UpdaterFactory is an interface that contains the methods to create the concrete classes for the OS updater.
type UpdaterFactory interface {
	createRebooter() Rebooter
	createUpdater() Updater
	createDownloader(url string) Downloader
}

// GetOSUpdaterFactory returns the correct concrete classes for the OS updater based on the OS type.
func GetOSUpdaterFactory(os string) (UpdaterFactory, error) {
	if os == "Emt" {
		return &EmtUpdater{}, nil
	}

	if os == "Ubuntu" {
		return &UbuntuUpdater{}, nil
	}
	return nil, fmt.Errorf("Unsupported OS")
}

// CreateDownloader creates a downloader concrete class for Emt OS.	
func (t *EmtUpdater) createDownloader(url string) Downloader {
	return &EmtDownloader{url: url}
}

// CreateOSUpdater creates an OS updater concrete class for Emt OS.
func (t *EmtUpdater) createUpdater() Updater {
	return &EmtUpdater{}
}

// CreateRebooter creates a rebooter concrete class for Emt OS.
func (t *EmtUpdater) createRebooter() Rebooter {
	return &EmtRebooter{}
}

// CreateDownloader creates a downloader concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createDownloader() Downloader {
	return &UbuntuDownloader{}
}

// CreateOSUpdater creates an OS updater concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createUpdater() Updater {
	return &UbuntuUpdater{}
}

// CreateRebooter creates a rebooter concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createRebooter() Rebooter {
	return &UbuntuRebooter{}
}
