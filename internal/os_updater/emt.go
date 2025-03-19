/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"golang.org/x/sys/unix"
)

var (
	configFilePath = "/etc/intel_manageability.conf"
	jwtTokenPath   = "/etc/intel_edge_node/tokens/release-service/access_token"
	downloadDir    = "/var/cache/manageability/repository-tool/sota"
	// OsUpdateTool will be changed in 3.1 release. Have to change the name and API call.
	// Check https://github.com/intel-sandbox/os.linux.tiberos.ab-update.go/blob/main/README.md
	osUpdateToolPath = "/usr/bin/os-update-tool.sh"
)

// EmtDownloader is the concrete implementation of the IDownloader interface
// for the Emt OS.
type EmtDownloader struct {
	request pb.UpdateSystemSoftwareRequest
}

func NewEmtDownloader(request pb.UpdateSystemSoftwareRequest) *EmtDownloader {
	return &EmtDownloader{
		request: request,
	}
}

// download implements IDownloader.
func (t *EmtDownloader) Download() error {
	config, err := LoadConfig(configFilePath)
	if err != nil {
		fmt.Println("Error loading intel_manageability.conf:", err)
		return err
	}

	// Perform source verification
	if !IsTrustedRepository(t.request.Url, config) {
		errMsg := fmt.Sprintf("URL '%s' is not in the list of trusted repositories.", t.request.Url)
		fmt.Println(errMsg)
		return fmt.Errorf(errMsg)
	}

	fmt.Println("Downloading update from", t.request.Url)

	// Check available space on disk
	isDiskEnough, err := t.checkDiskSpace()
	if err != nil {
		fmt.Println("Error checking disk space:", err)
		return fmt.Errorf(err.Error())
	}

	if !isDiskEnough {
		errMsg := "Insufficient disk space."
		fmt.Println(errMsg)
		return fmt.Errorf(errMsg)
	}

	fmt.Println("Disk space enough. Proceeding to download the artifact.")

	// Download file
	err = t.downloadFile()
	if err != nil {
		fmt.Println("Error downloading the file:", err)
		return err
	}

	fmt.Println("Download completed.")

	return nil

}

// readJwtToken reads the JWT token that is used for accessing RS server.
func (t *EmtDownloader) readJwtToken() (string, error) {
	file, err := os.Open(jwtTokenPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	token, err := os.ReadFile(jwtTokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

// checkDiskSpace checks if there is enough disk space to download the artifacts.
func (t *EmtDownloader) checkDiskSpace() (bool, error) {
	// Get available disk space
	var stat unix.Statfs_t
	err := unix.Statfs("/var/cache/manageability/", &stat)
	if err != nil {
		fmt.Printf("Error getting disk space: %v\n", err)
		return false, err
	}
	availableSpace := stat.Bavail * uint64(stat.Bsize)

	//Read JWT token
	token, err := t.readJwtToken()
	if err != nil {
		fmt.Println("Error reading JWT token:", err)
		return false, err
	}

	// Check if the token exists
	if token == "" {
		errMsg := "JWT token is empty."
		fmt.Println(errMsg)
		return false, fmt.Errorf(errMsg)
	}

	// Create a new HTTP request
	req, err := http.NewRequest("HEAD", t.request.Url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return false, err
	}

	// Add the JWT token to the request header
	req.Header.Add("Authorization", "Bearer "+token)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error performing request: %v\n", err)
		return false, err
	}
	defer resp.Body.Close()

	// Get the Content-Length header
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		fmt.Println("Content-Length header is missing. Falling back to GET request.")
		// Perform a GET request to determine the file size
		req.Method = "GET"
		resp, err = client.Do(req)
		if err != nil {
			fmt.Printf("Error performing GET request: %v\n", err)
			return false, err
		}
		defer resp.Body.Close()

		// Get the Content-Length header from the GET response
		contentLength = resp.Header.Get("Content-Length")
		if contentLength == "" {
			fmt.Println("Content-Length header is still missing after GET request.")
			return false, fmt.Errorf("Content-Length header is missing")
		}
	}

	// Parse the Content-Length to an integer
	var requiredSpace uint64
	_, err = fmt.Sscanf(contentLength, "%d", &requiredSpace)
	if err != nil {
		fmt.Printf("Error parsing Content-Length: %v\n", err)
		return false, err
	}

	// Check if there is enough space
	if availableSpace < requiredSpace {
		return false, nil
	}
	return true, nil

}

// downloadFile downloads the file from the url.
func (t *EmtDownloader) downloadFile() error {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", t.request.Url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return err
	}

	// Add the JWT token to the request header
	token, err := t.readJwtToken()
	if err != nil {
		fmt.Println("Error reading JWT token:", err)
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error performing request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Extract the file name from the URL
	urlParts := strings.Split(t.request.Url, "/")
	fileName := urlParts[len(urlParts)-1]

	// Create the file
	file, err := os.Create(downloadDir + "/" + fileName)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return err
	}
	defer file.Close()

	// Copy the response body to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Printf("Error downloading file: %v\n", err)
		return err
	}

	return nil

}

// EmtUpdater is the concrete implementation of the IUpdater interface
// for the Emt OS.
type EmtUpdater struct {
	commandExecutor utils.Executor
	request         pb.UpdateSystemSoftwareRequest
}

func NewEmtUpdater(commandExecutor utils.Executor, request pb.UpdateSystemSoftwareRequest) *EmtUpdater {
	return &EmtUpdater{
		commandExecutor: commandExecutor,
		request:         request,
	}
}

// Update method for Emt
func (tu *EmtUpdater) Update() error {

	if tu.request.Mode == pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY {
		fmt.Println("Execute update tool write command.")

		// Extract the file name from the URL
		urlParts := strings.Split(tu.request.Url, "/")
		fileName := urlParts[len(urlParts)-1]

		// Create the file
		filePath := downloadDir + "/" + fileName

		updateToolWriteCommand := []string{
			"sudo", osUpdateToolPath, "-w", "-u", filePath, "-s", tu.request.Signature,
		}
		if _, err := tu.commandExecutor.Execute(updateToolWriteCommand); err != nil {
			return fmt.Errorf("failed to execute shell command(%v)- %v", updateToolWriteCommand, err)
		}
	}

	if tu.request.Mode == pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD {
		fmt.Println("Execute update tool apply command.")
		updateToolApplyCommand := []string{
			"sudo", osUpdateToolPath, "-a",
		}
		if _, err := tu.commandExecutor.Execute(updateToolApplyCommand); err != nil {
			return fmt.Errorf("failed to execute shell command(%v)- %v", updateToolApplyCommand, err)
		}
	}

	return nil

}

// EmtRebooter is the concrete implementation of the IUpdater interface
// for the Emt OS.
type EmtRebooter struct{}

// Reboot method for Emt
func (tu *EmtRebooter) Reboot() error {
	panic("unimplemented")
}
