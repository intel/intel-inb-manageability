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

// UbuntuDownloader is the concrete implementation of the IDownloader interface
// for the Ubuntu OS.
type UbuntuDownloader struct {
	request *pb.UpdateSystemSoftwareRequest
}

// Download method for Ubuntu
func (u *UbuntuDownloader) Download() error {
	panic("unimplemented")
}

// UbuntuUpdater is the concrete implementation of the IUpdater interface
// for the Ubuntu OS.
type UbuntuUpdater struct {
	commandExecutor utils.Executor
	request         *pb.UpdateSystemSoftwareRequest
}

// Update method for Ubuntu
func (u *UbuntuUpdater) Update() error {
	panic("unimplemented")
}

// UbuntuRebooter is the concrete implementation of the IUpdater interface
// for the Ubuntu OS.
type UbuntuRebooter struct {
	commandExecutor utils.Executor
	request         *pb.UpdateSystemSoftwareRequest
}

// Reboot method for Ubuntu
func (u *UbuntuRebooter) Reboot() error {
	panic("unimplemented")
}
