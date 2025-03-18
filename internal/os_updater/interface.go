/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"fmt"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// UpdaterFactory is an interface that contains the methods to create the concrete classes for the OS updater.
type UpdaterFactory interface {
	CreateDownloader(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader
	CreateUpdater() Updater
	CreateRebooter() Rebooter	
}

// GetOSUpdaterFactory returns the correct concrete classes for the OS updater based on the OS type.
func GetOSUpdaterFactory(os string) (UpdaterFactory, error) {
	if os == "EMT" {
		return &EMTFactory{}, nil
	}

	if os == "Ubuntu" {
		return &UbuntuFactory{}, nil
	}
	return nil, fmt.Errorf("Unsupported OS")
}

// EMTFactory represents an EMT factory.
type EMTFactory struct{}

// CreateDownloader creates a downloader concrete class for EMT OS.
func (f *EMTFactory) CreateDownloader(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
	return &EMTDownloader{}
}


// CreateUpdater creates an OS updater concrete class for EMT OS.
func (f *EMTFactory) CreateUpdater() Updater {
	return &EMTUpdater{}
}

// CreateRebooter creates a rebooter concrete class for EMT OS.
func (f *EMTFactory) CreateRebooter() Rebooter {
	return &EMTRebooter{}
}

// UbuntuFactory represents an EMT factory.
type UbuntuFactory struct{}

// CreateDownloader creates a downloader concrete class for EMT OS.
func (f *UbuntuFactory) CreateDownloader(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
	return &UbuntuDownloader{}
}

// CreateUpdater creates an OS updater concrete class for Ubuntu OS.
func (f *UbuntuFactory) CreateUpdater() Updater {
	return &UbuntuUpdater{}
}

// CreateRebooter creates a rebooter concrete class for Ubuntu OS.
func (f *UbuntuFactory) CreateRebooter() Rebooter {
	return &UbuntuRebooter{}
}
