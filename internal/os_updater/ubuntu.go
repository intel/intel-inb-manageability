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
	fmt.Printf("Debian-based OS does not require a file download to perform a software update")
	return nil
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
	fmt.Print("Rebooting ")
	time.Sleep(2 * time.Second)
	
	isDockerApp := os.Getenv("container") != ""
	cmd := "/sbin/reboot"

	if isDockerApp {
		_, err := execCommand(DockerChrootPrefix + cmd)
		if err != nil {
			return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
		}
	} else {
		_, err := execCommand(cmd)
		if err != nil {
			return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
		}
	}
	return nil
}
