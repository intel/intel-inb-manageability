/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"fmt"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// UpdaterFactory is an interface that contains the methods to create the concrete classes for the OS updater.
type UpdaterFactory interface {
	CreateDownloader(req *pb.UpdateSystemSoftwareRequest) Downloader
	CreateUpdater(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Updater
	CreateRebooter(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Rebooter
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
func (f *EMTFactory) CreateDownloader(req *pb.UpdateSystemSoftwareRequest) Downloader {
	return NewEMTDownloader(req)
}

// CreateUpdater creates an OS updater concrete class for EMT OS.
func (f *EMTFactory) CreateUpdater(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Updater {
	return NewEMTUpdater(commandExecutor, req)
}

// CreateRebooter creates a rebooter concrete class for EMT OS.
func (f *EMTFactory) CreateRebooter(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Rebooter {
	return NewEMTRebooter(commandExecutor, req)
}

// UbuntuFactory represents an EMT factory.
type UbuntuFactory struct{}

// CreateDownloader creates a downloader concrete class for EMT OS.
func (f *UbuntuFactory) CreateDownloader(req *pb.UpdateSystemSoftwareRequest) Downloader {
	return &UbuntuDownloader{request: req}
}

// CreateUpdater creates an OS updater concrete class for Ubuntu OS.
func (f *UbuntuFactory) CreateUpdater(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Updater {
	return &UbuntuUpdater{
		commandExecutor: commandExecutor,
		request:         req,
	}
}

// CreateRebooter creates a rebooter concrete class for Ubuntu OS.
func (f *UbuntuFactory) CreateRebooter(commandExecutor utils.Executor, req *pb.UpdateSystemSoftwareRequest) Rebooter {
	return &UbuntuRebooter{
		commandExecutor: commandExecutor,
		request:         req,
	}
}
