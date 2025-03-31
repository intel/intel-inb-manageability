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
	commandExecutor         utils.Executor
	request                 *pb.UpdateSystemSoftwareRequest
	getEstimatedSize        func(cmdExec utils.Executor) (bool, uint64, error)
	getFreeDiskSpaceInBytes func(path string) (uint64, error)
}

// Update method for Ubuntu
func (u *UbuntuUpdater) Update() (bool, error) {
	// Set the environment variable DEBIAN_FRONTEND to noninteractive
	err := os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	if err != nil {
		return false, fmt.Errorf("SOTA Aborted: Failed to set environment variable: %v", err)
	}

	err = os.Setenv("PATH", os.Getenv("PATH")+":/usr/bin:/bin")
	if err != nil {
		return false, fmt.Errorf("SOTA Aborted: Failed to set environment variable: %v", err)
	}

	isUpdateAvail, updateSize, err := u.getEstimatedSize(u.commandExecutor)
	if err != nil {
		return false, fmt.Errorf("SOTA Aborted: Update Failed: %s", err)
	}
	if !isUpdateAvail {
		log.Println("No update available.  System is up to date.")
		return false, nil
	}

	log.Printf("Estimated update size: %d bytes", updateSize)

	freeSpace, err := u.getFreeDiskSpaceInBytes("/")
	if err != nil {
		return false, fmt.Errorf("SOTA Aborted: Failed to get free disk space: %v", err)
	}
	log.Printf("Free disk space: %d bytes", freeSpace)
	if freeSpace < updateSize {
		return false, fmt.Errorf("SOTA Aborted: Not enough free disk space.  Free: %d bytes, Required: %d bytes", freeSpace, updateSize)
	}

	var cmds [][]string
	switch u.request.Mode {
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL:
		cmds = fullInstall(u.request.PackageList)
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD:
		cmds = noDownload(u.request.PackageList)
	case pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY:
		cmds = downloadOnly(u.request.PackageList)
	default:
		return false, fmt.Errorf("SOTA Aborted: Invalid mode")
	}

	for _, cmd := range cmds {
		log.Printf("Executing command: %s", cmd)
		_, stderr, _ := u.commandExecutor.Execute(cmd)
		if len(stderr) > 0 {
			return false, fmt.Errorf("SOTA Aborted: Command failed: %s", string(stderr))
		}
	}

	return true, nil
}

func getEstimatedSize(cmdExec utils.Executor) (bool, uint64, error) {
	cmd := []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o",
		"Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}

	// Ignore the error as the command will return a non-zero exit code
	stdout, stderr, _ := cmdExec.Execute(cmd)
	if len(stderr) > 0 {
		log.Printf("Error executing command: %s", string(stderr))
	}
	return getEstimatedSizeInBytesFromAptGetUpgrade(string(stdout))
}

func sizeToBytes(size string, unit string) uint64 {
	parsedSize, err := strconv.ParseFloat(size, 64)
	if err != nil {
		log.Printf("Error parsing size: %v", err)
		return 0
	}

	switch unit {
	case "kB":
		return uint64(parsedSize * 1024)
	case "MB":
		return uint64(parsedSize * 1024 * 1024)
	case "GB":
		return uint64(parsedSize * 1024 * 1024 * 1024)
	default:
		return uint64(parsedSize)
	}
}

const noUpdateAvailable = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."

func getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput string) (bool, uint64, error) {
	log.Printf("Apt-get upgrade output: %s", upgradeOutput)
	var outputLines []string
	for _, line := range strings.Split(upgradeOutput, "\n") {
		if strings.Contains(line, "After this operation,") {
			outputLines = append(outputLines, line)
		} else if strings.Contains(line, noUpdateAvailable) {
			// No update available.  System is up to date
			return false, 0, nil
		}

	}
	output := strings.Join(outputLines, "\n")

	updateRegex := regexp.MustCompile(`(\d+(?:,\d+)*(\.\d+)?)(\s*(kB|B|MB|GB)).*(freed|used)`)
	matches := updateRegex.FindStringSubmatch(output)

	if matches == nil {
		return false, 0, fmt.Errorf("failed to get size of the update")
	}

	freedOrUsed := matches[5]

	if freedOrUsed == "used" {
		sizeString := strings.Replace(matches[1], ",", "", -1)
		return true, sizeToBytes(sizeString, matches[4]), nil
	}

	log.Println("Update will free some size on disk")
	return true, 0, nil
}

func noDownload(packages []string) [][]string {
	log.Println("No download mode")
	cmds := [][]string{
		{"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"},
		{"apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o",
			"Dpkg::Options::='--force-confold'", "-yq", "-f", "install"},
	}

	if len(packages) == 0 {
		cmds = append(cmds, []string{"apt-get", "-o",
			"Dpkg::Options::='--force-confdef'", "-o",
			"Dpkg::Options::='--force-confold'",
			"--with-new-pkgs", "--no-download",
			"--fix-missing", "-yq", "upgrade"})
	} else {
		cmds = append(cmds, [][]string{append([]string{"apt-get", "-o",
			"Dpkg::Options::='--force-confdef'", "-o",
			"Dpkg::Options::='--force-confold'",
			"--no-download", "--fix-missing", "-yq",
			"install"}, packages...)}...)
	}

	return cmds
}

func downloadOnly(packages []string) [][]string {
	log.Println("Download only mode")

	cmds := [][]string{
		{"apt-get", "update"},
		{"dpkg-query", "-f", "'${binary:Package}\\n'", "-W"},
	}

	if len(packages) == 0 {
		cmds = append(cmds, []string{"apt-get", "-o",
			"Dpkg::Options::='--force-confdef'", "-o",
			"Dpkg::Options::='--force-confold'",
			"--with-new-pkgs", "--download-only",
			"--fix-missing", "-yq", "upgrade"})
	} else {
		cmds = append(cmds, [][]string{append([]string{"apt-get", "-o",
			"Dpkg::Options::='--force-confdef'", "-o",
			"Dpkg::Options::='--force-confold'", "--download-only",
			"--fix-missing", "-yq", "install"}, packages...)}...)
	}

	return cmds
}

func fullInstall(packages []string) [][]string {
	log.Println("Download and install mode")

	cmds := [][]string{
		{"/usr/bin/apt-get", "update"},
		{"dpkg-query -W -f='${binary:Package}\\n'"},
		{"dpkg --configure -a --force-confdef --force-confold"},
		{"apt-get -yq -f -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install"},
		{"apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"}}

	if len(packages) == 0 {
		cmds = append(cmds, []string{"apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --with-new-pkgs upgrade"})
	} else {
		cmds = append(cmds, []string{"apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install"})
		cmds = append(cmds, packages)
	}

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
	if u.request.DoNotReboot {
		log.Println("Reboot is disabled.  Skipping reboot.")
		return nil
	}

	fmt.Print("Rebooting ")
	time.Sleep(2 * time.Second)

	cmd := "/sbin/reboot"

	_, _, err := u.commandExecutor.Execute([]string{cmd})
	if err != nil {
		return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
	}

	return nil
}
