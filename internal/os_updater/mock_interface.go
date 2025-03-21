/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// MockDownloader is a mock implementation of the Downloader interface.
type MockDownloader struct {
	DownloadFunc func() error
}

// Download calls the DownloadFunc.
func (m *MockDownloader) Download() error {
	return m.DownloadFunc()
}

// MockUpdater is a mock implementation of the Updater interface.
type MockUpdater struct {
	UpdateFunc func() error
}

// Update calls the UpdateFunc.
func (m *MockUpdater) Update() error {
	return m.UpdateFunc()
}

// MockRebooter is a mock implementation of the Rebooter interface.
type MockRebooter struct {
	RebootFunc func() error
}

// Reboot calls the RebootFunc.
func (m *MockRebooter) Reboot() error {
	return m.RebootFunc()
}

// MockUpdaterFactory is a mock implementation of the UpdaterFactory interface.
type MockUpdaterFactory struct {
	CreateDownloaderFunc func(*pb.UpdateSystemSoftwareRequest) Downloader
	CreateUpdaterFunc    func(utils.Executor, *pb.UpdateSystemSoftwareRequest) Updater
	CreateRebooterFunc   func(utils.Executor, *pb.UpdateSystemSoftwareRequest) Rebooter
}

// CreateDownloader calls the CreateDownloaderFunc.
func (m *MockUpdaterFactory) CreateDownloader(req *pb.UpdateSystemSoftwareRequest) Downloader {
	return m.CreateDownloaderFunc(req)
}

// CreateUpdater calls the CreateUpdaterFunc.
func (m *MockUpdaterFactory) CreateUpdater(cmdExec utils.Executor, req *pb.UpdateSystemSoftwareRequest) Updater {
	return m.CreateUpdaterFunc(cmdExec, req)
}

// CreateRebooter calls the CreateRebooterFunc.
func (m *MockUpdaterFactory) CreateRebooter(cmdExec utils.Executor, req *pb.UpdateSystemSoftwareRequest) Rebooter {
	return m.CreateRebooterFunc(cmdExec, req)
}
