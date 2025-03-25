/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package osupdater

import (
	"os/exec"
	"testing"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetOSUpdaterFactory(t *testing.T) {
	t.Run("returns EMTUpdater for EMT OS", func(t *testing.T) {
		factory, err := GetOSUpdaterFactory("EMT")
		assert.NoError(t, err)
		assert.IsType(t, &EMTFactory{}, factory)
	})

	t.Run("returns UbuntuUpdater for Ubuntu OS", func(t *testing.T) {
		factory, err := GetOSUpdaterFactory("Ubuntu")
		assert.NoError(t, err)
		assert.IsType(t, &UbuntuFactory{}, factory)
	})

	t.Run("returns error for unsupported OS", func(t *testing.T) {
		factory, err := GetOSUpdaterFactory("UnsupportedOS")
		assert.Error(t, err)
		assert.Nil(t, factory)
	})
}

func TestEMTUpdater(t *testing.T) {
	emtUpdater := &EMTFactory{}
	req := &pb.UpdateSystemSoftwareRequest{
		Mode:        pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY,
		DoNotReboot: true,
		Signature:   "signature",
	}

	t.Run("createDownloader returns EMTDownloader", func(t *testing.T) {
		downloader := emtUpdater.CreateDownloader(req)
		assert.IsType(t, &EMTDownloader{}, downloader)
	})

	t.Run("createUpdater returns EMTUpdater", func(t *testing.T) {
		updater := emtUpdater.CreateUpdater(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), req)
		assert.IsType(t, &EMTUpdater{}, updater)
	})

	t.Run("createRebooter returns EMTRebooter", func(t *testing.T) {
		rebooter := emtUpdater.CreateRebooter(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), req)
		assert.IsType(t, &EMTRebooter{}, rebooter)
	})
}

func TestUbuntuUpdater(t *testing.T) {
	ubuntuUpdater := &UbuntuFactory{}
	req := pb.UpdateSystemSoftwareRequest{
		Mode:        pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY,
		DoNotReboot: true,
		Signature:   "signature",
	}

	t.Run("createDownloader returns UbuntuDownloader", func(t *testing.T) {
		downloader := ubuntuUpdater.CreateDownloader(&req)
		assert.IsType(t, &UbuntuDownloader{}, downloader)
	})

	t.Run("createUpdater returns UbuntuUpdater", func(t *testing.T) {
		updater := ubuntuUpdater.CreateUpdater(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), &req)
		assert.IsType(t, &UbuntuUpdater{}, updater)
	})

	t.Run("createRebooter returns UbuntuRebooter", func(t *testing.T) {
		rebooter := ubuntuUpdater.CreateRebooter(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), &req)
		assert.IsType(t, &UbuntuRebooter{}, rebooter)
	})
}
