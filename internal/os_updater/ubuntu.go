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
	"regexp"
	"strconv"
	"strings"
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
	updateSize, err := getEstimatedSize(u.commandExecutor)
	if err != nil {
		return fmt.Errorf("SOTA Aborted: Update Failed: %s", err)
	}
	log.Printf("Estimated update size: %d bytes", updateSize)

	// TODO:  Check to make sure there is enough space.

	var cmds []string
	switch u.request.Mode {
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY:
		cmds = downloadOnly(u.request.PackageList)
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD:
		cmds = noDownload(u.request.PackageList)
	default:
		return fmt.Errorf("SOTA Aborted: Invalid mode")
	}

	_, err = u.commandExecutor.Execute(cmds)
	if err != nil {
		return fmt.Errorf("SOTA Aborted: Update Failed: %s", err)
	}

	// Write the update status to the status log file
	err = writeUpdateStatus(SUCCESS, string("SOTA command status: SUCCESSFUL"), "")
	if err != nil {
		fmt.Printf("[Warning] Error writing update status: %v", err)
	}

	return nil
}

func getEstimatedSize(cmdExec utils.Executor) (int64, error) {
	cmd := []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o",
	"Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}

	// Ignore the error as the command will return a non-zero exit code
	output, _ := cmdExec.Execute(cmd)
	

	return getEstimatedSizeInBytesFromAptGetUpgrade(string(output))
}

func sizeToBytes(size string, unit string) int64 {
	log.Printf("Size: %s, Unit: %s", size, unit)
	parsedSize, err := strconv.ParseFloat(size, 64)
	if err != nil {
		log.Printf("Error parsing size: %v", err)
		return 0
	}

	switch unit {
	case "kB":
		return int64(parsedSize * 1024)
	case "MB":
		return int64(parsedSize * 1024 * 1024)
	case "GB":
		return int64(parsedSize * 1024 * 1024 * 1024)
	default:
		return int64(parsedSize)
	}
}

func getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput string) (int64, error) {
	log.Printf("Apt-get upgrade output: %s", upgradeOutput)
	var outputLines []string
	for _, line :=range strings.Split(upgradeOutput, "\n") {
		if strings.Contains(line, "After this operation,") {
			outputLines = append(outputLines, line)
		}
	}
	output := strings.Join(outputLines, "\n")

	updateRegex := regexp.MustCompile(`(\d+(?:,\d+)*(\.\d+)?)(\s*(kB|B|MB|GB)).*(freed|used)`)
	matches := updateRegex.FindStringSubmatch(output)

	if matches == nil {
		return 0, fmt.Errorf("failed to get size of the update")
	}
	
	freedOrUsed := matches[5]

	if freedOrUsed == "used" {
		sizeString := strings.Replace(matches[1], ",", "", -1)
		return sizeToBytes(sizeString, matches[4]), nil
	}

	log.Println("Update will free some size on disk")
	return 0, nil
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
		installCmd = append(installCmd, "apt-get", "-o", 
			"Dpkg::Options::='--force-confdef'", "-o", 
			"Dpkg::Options::='--force-confold'", 
			"--with-new-pkgs", "--no-download", 
			"--fix-missing", "-yq", "upgrade")
	} else {
		installCmd = append(installCmd, append([]string{"apt-get", "-o", 
		"Dpkg::Options::='--force-confdef'", "-o", 
		"Dpkg::Options::='--force-confold'", 
		"--no-download", "--fix-missing", "-yq", 
		"install"}, packages...)...)
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
		installCmd = append(installCmd, "apt-get", "-o", 
			"Dpkg::Options::='--force-confdef'", "-o", 
			"Dpkg::Options::='--force-confold'", 
			"--with-new-pkgs", "--download-only", 
			"--fix-missing", "-yq", "upgrade")
	} else {
		installCmd = append(installCmd, append([]string{"apt-get", "-o", 
		"Dpkg::Options::='--force-confdef'", "-o", 
		"Dpkg::Options::='--force-confold'", "--download-only", 
		"--fix-missing", "-yq", "install"}, packages...)...)
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
