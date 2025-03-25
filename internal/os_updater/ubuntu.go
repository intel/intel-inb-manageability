/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"fmt"
	"log"
	"os"
	"time"

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

// UbuntuUpdater is the concrete implementation of the Updater interface
// for the Ubuntu OS.
type UbuntuUpdater struct {
	commandExecutor utils.Executor
	request         *pb.UpdateSystemSoftwareRequest
}

// Update method for Ubuntu
func (u *UbuntuUpdater) Update() error {

	cmds := []string{}
	switch u.request.Mode {
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY:
		cmds = downloadOnly(u.request.PackageList)
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD:
		cmds = noDownload(u.request.PackageList)
	default:
		return fmt.Errorf("SOTA Aborted: Invalid mode")
	}

	_, err := u.commandExecutor.Execute(cmds)
	if err != nil {
		return fmt.Errorf("SOTA Aborted: Update Failed: %s", err)
	}
	return nil
}

func noDownload(packages []string) []string {
	log.Println("No download mode")
	var cmds []string
	cmds = append(cmds, "dpkg", "--configure", "-a", 
				"--force-confdef", 
				"--force-confold", 
				"apt-get", "-o", 
				"Dpkg::Options::='--force-confdef'", "-o", 
				"Dpkg::Options::='--force-confold'", "-yq",
				"-f", "install")

	var installCmd []string
	if len(packages) == 0 {
		installCmd = append([]string{"apt-get", "-o", 
			"Dpkg::Options::='--force-confdef'", "-o", 
			"Dpkg::Options::='--force-confold'", 
			"--with-new-pkgs", "--no-download", 
			"--fix-missing", "-yq", "upgrade"})
	} else {
		installCmd = append([]string{"apt-get", "-o", 
		"Dpkg::Options::='--force-confdef'", "-o", 
		"Dpkg::Options::='--force-confold'", 
		"--no-download", "--fix-missing", "-yq", 
		"install"}, packages...)
	}

	cmds = append(cmds, installCmd...)
	return cmds
}

func downloadOnly(packages []string) []string {
	log.Println("Download only mode")
	var cmds []string
	cmds = append(cmds, "apt-get", "update", "dpkg-query", "-f", "-a", "'${binary:Package}\\n'", "-W")
	
	var installCmd []string
	if len(packages) == 0 {
		installCmd =append([]string{"apt-get", "-o", 
			"Dpkg::Options::='--force-confdef'", "-o", 
			"Dpkg::Options::='--force-confold'", 
			"--with-new-pkgs", "--download-only", 
			"--fix-missing", "-yq", "upgrade"})
	} else {
		installCmd = append([]string{"apt-get", "-o", 
		"Dpkg::Options::='--force-confdef'", "-o", 
		"Dpkg::Options::='--force-confold'", "--download-only", 
		"--fix-missing", "-yq", "install"}, packages...)
	}
	cmds = append(cmds, installCmd...)
	return cmds
}

// UbuntuRebooter is the concrete implementation of the Updater interface
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
		_, err := u.commandExecutor.Execute([]string{DockerChrootPrefix, cmd})
		if err != nil {
			return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
		}
	} else {
		_, err := u.commandExecutor.Execute([]string{cmd})
		if err != nil {
			return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
		}
	}
	return nil
}
