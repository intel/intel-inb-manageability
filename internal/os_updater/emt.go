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
	"strings"
	"syscall"
)

var (
	configFilePath = "/etc/intel_manageability.conf"
	jwtTokenPath   = "/etc/intel_edge_node/tokens/release-service/access_token"
	downloadDir    = "/var/cache/manageability/repository-tool/sota"
	// OsUpdateTool will be changed in 3.1 release. Have to change the name and API call.
	// Check https://github.com/intel-sandbox/os.linux.tiberos.ab-update.go/blob/main/README.md
	osUpdateToolPath = "/usr/bin/os-update-tool.sh"

	inbcSotaDownloadOnlyCommand = []string{
		"sudo", "inbc", "sota", "--mode", "download-only", "--reboot", "no",
	}
)

// EmtDownloader is the concrete implementation of the IDownloader interface
// for the Emt OS.
type EmtDownloader struct {
	url string // download link url
}

// download implements IDownloader.
func (t *EmtDownloader) download() error {
	config, err := LoadConfig(configFilePath)
	if err != nil {
		fmt.Println("Error loading intel_manageability.conf:", err)
		return err
	}

	// Perform source verification
	if !IsTrustedRepository(t.url, config) {
		return fmt.Errorf("URL is not in the list of trusted repositories.")
	}

	fmt.Println("Downloading update from", t.url)

	// Check available space on disk
	if !t.checkDiskSpace() {
		return fmt.Errorf("Insufficient disk space.")
	}

	fmt.Println("Disk space enough. Proceeding to download the artifact.")

	t.downloadFile()

	fmt.Println("Download completed.")

	return nil

}

// readJwtToken reads the JWT token that is used for accessing RS server.
func (t *EmtDownloader) readJwtToken() (string, error) {
	file, err := os.Open(jwtTokenPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	token, err := os.Readfile(file)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// checkDiskSpace checks if there is enough disk space to download the artifacts.
func (t *EmtDownloader) checkDiskSpace() bool {
	// Get available disk space
	var stat syscall.Statfs_t
	syscall.Statfs("/var/cache/manageability/", &stat)
	availableSpace := stat.Bavail * uint64(stat.Bsize)

	//Read JWT token
	token, err := t.readJwtToken()
	if err != nil {
		fmt.Println("Error reading JWT token:", err)
		return err
	}

	// Create a new HTTP request
	req, err := http.NewRequest("HEAD", t.url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Add the JWT token to the request header
	req.Header.Add("Authorization", "Bearer "+jwtToken)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error performing request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Get the Content-Length header
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		fmt.Println("Content-Length header is missing")
		return
	}

	// Parse the Content-Length to an integer
	var requiredSpace uint64
	_, err = fmt.Sscanf(contentLength, "%d", &requiredSpace)
	if err != nil {
		fmt.Printf("Error parsing Content-Length: %v\n", err)
		return
	}

	// Check if there is enough space
	if availableSpace < requiredSpace {
		return false
	}
	return true

}

// downloadFile downloads the file from the url.
func (t *EmtDownloader) downloadFile() error {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", t.url, nil)
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
	urlParts := strings.Split(t.url, "/")
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
type EmtUpdater struct{}

// Update method for Emt
func (tu *EmtUpdater) update(mode string) error {

	if mode == "download-only" {
		fmt.Println("Execute download-only command for Emt OS.")

	}

	if mode == "no-download" {
		fmt.Println("Execute no-download command for Emt OS.")
		panic("unimplemented")
	}

}

// EmtRebooter is the concrete implementation of the IUpdater interface
// for the Emt OS.
type EmtRebooter struct{}

// Reboot method for Emt
func (tu *EmtRebooter) reboot() error {
	panic("unimplemented")
}
