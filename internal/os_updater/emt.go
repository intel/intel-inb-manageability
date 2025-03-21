/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/spf13/afero"
	"golang.org/x/sys/unix"
)

var (
	configFilePath = "/etc/intel_manageability.conf"
	JWTTokenPath   = "/etc/intel_edge_node/tokens/release-service/access_token"
	downloadDir    = "/var/cache/manageability/repository-tool/sota"
	// OsUpdateTool will be changed in 3.1 release. Have to change the name and API call.
	// Check https://github.com/intel-sandbox/os.linux.tiberos.ab-update.go/blob/main/README.md
	osUpdateToolPath = "/usr/bin/os-update-tool.sh"
)

// EMTDownloader is the concrete implementation of the IDownloader interface
// for the Emt OS.
type EMTDownloader struct {
	request          *pb.UpdateSystemSoftwareRequest
	readJWTTokenFunc func() (string, error)
	statfs           func(path string, stat *unix.Statfs_t) error
	httpClient       *http.Client
	requestCreator   func(method string, url string, body io.Reader) (*http.Request, error)
	fs               afero.Fs
}

// NewEMTDownloader creates a new EMTDownloader.
func NewEMTDownloader(request *pb.UpdateSystemSoftwareRequest) *EMTDownloader {
	return &EMTDownloader{
		request:          request,
		readJWTTokenFunc: defaultReadJWTToken,
		statfs:           unix.Statfs,
		httpClient:       &http.Client{},
		requestCreator:   http.NewRequest,
		fs:               afero.NewOsFs(),
	}
}

func defaultReadJWTToken() (string, error) {
	file, err := os.Open(JWTTokenPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	token, err := os.ReadFile(JWTTokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

// Download implements IDownloader.
func (t *EMTDownloader) Download() error {
	config, err := LoadConfig(configFilePath)
	if err != nil {
		fmt.Println("Error loading intel_manageability.conf:", err)
		return err
	}

	// Perform source verification
	if !IsTrustedRepository(t.request.Url, config) {
		errMsg := fmt.Sprintf("URL '%s' is not in the list of trusted repositories.", t.request.Url)
		fmt.Println(errMsg)
		return errors.New(errMsg)
	}

	fmt.Println("Downloading update from", t.request.Url)

	// Check available space on disk
	isDiskEnough, err := t.checkDiskSpace()
	if err != nil {
		fmt.Println("Error checking disk space:", err)
		return errors.New(err.Error())
	}

	if !isDiskEnough {
		errMsg := "Insufficient disk space."
		fmt.Println(errMsg)
		return errors.New(errMsg)
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

// readJWTToken reads the JWT token that is used for accessing RS server.
func (t *EMTDownloader) readJWTToken() (string, error) {
	file, err := t.fs.Open(JWTTokenPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	token, err := afero.ReadFile(t.fs, JWTTokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

// checkDiskSpace checks if there is enough disk space to download the artifacts.
func (t *EMTDownloader) checkDiskSpace() (bool, error) {
	// Get available disk space
	var stat unix.Statfs_t
	err := t.statfs("/var/cache/manageability/", &stat)
	if err != nil {
		fmt.Printf("Error getting disk space: %v\n", err)
		return false, err
	}
	availableSpace := stat.Bavail * uint64(stat.Bsize)

	//Read JWT token
	token, err := t.readJWTTokenFunc()
	if err != nil {
		fmt.Println("Error reading JWT token:", err)
		return false, err
	}

	// Check if the token exists
	if token == "" {
		errMsg := "empty JWT token"
		fmt.Println(errMsg)
		return false, errors.New(errMsg)
	}

	if t.requestCreator == nil {
		fmt.Println("requestCreator is nil")
	}
	if t.httpClient == nil {
		fmt.Println("httpClient is nil")
	}
	// Create a new HTTP request
	req, err := t.requestCreator("HEAD", t.request.Url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return false, err
	}

	// Add the JWT token to the request header
	req.Header.Add("Authorization", "Bearer "+token)

	// Perform the request
	resp, err := t.httpClient.Do(req)
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
		resp, err = t.httpClient.Do(req)
		if err != nil {
			fmt.Printf("Error performing GET request: %v\n", err)
			return false, err
		}
		defer resp.Body.Close()

		// Get the Content-Length header from the GET response
		contentLength = resp.Header.Get("Content-Length")
		if contentLength == "" {
			fmt.Println("Content-Length header is still missing after GET request.")
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Error reading response body: %v\n", err)
				return false, err
			}
			fmt.Printf("Response Body: %s\n", string(body))
			return false, fmt.Errorf("Content-Length header is missing")
		}
		// Check if the status code is 200/Success. If not, return the error.
		if resp.StatusCode != http.StatusOK {
			errMsg := fmt.Sprintf("Status code: %d. Expected 200/Success.", resp.StatusCode)
			fmt.Println(errMsg)
			return false, errors.New(errMsg)
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
func (t *EMTDownloader) downloadFile() error {
	// Create a new HTTP request
	req, err := t.requestCreator("GET", t.request.Url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return err
	}

	// Add the JWT token to the request header
	token, err := t.readJWTTokenFunc()
	if err != nil {
		fmt.Println("Error reading JWT token:", err)
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)

	// Perform the request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		fmt.Printf("Error performing request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Check if the status code is 200/Success. If not, return the error.
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Status code: %d. Expected 200/Success.", resp.StatusCode)
		fmt.Println(errMsg)
		return errors.New(errMsg)
	}

	// Extract the file name from the URL
	urlParts := strings.Split(t.request.Url, "/")
	fileName := urlParts[len(urlParts)-1]

	// Create the file
	file, err := t.fs.Create(downloadDir + "/" + fileName)
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

// EMTUpdater is the concrete implementation of the IUpdater interface
// for the EMT OS.
type EMTUpdater struct {
	commandExecutor utils.Executor
	request         *pb.UpdateSystemSoftwareRequest
}

// NewEMTUpdater creates a new EMTUpdater.
func NewEMTUpdater(commandExecutor utils.Executor, request *pb.UpdateSystemSoftwareRequest) *EMTUpdater {
	return &EMTUpdater{
		commandExecutor: commandExecutor,
		request:         request,
	}
}

// errReader is a helper type to simulate an error during reading
type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error copying response body")
}

// Update method for Emt
func (tu *EMTUpdater) Update() error {
	// Print the value of tu.request.Mode
	fmt.Printf("Mode: %v\n", tu.request.Mode)
	if tu.request.Mode == pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY {

		err := tu.VerifyHash()
		if err != nil {
			fmt.Printf("Hash verification failed: %v\n", err)
			return err
		}

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

func (tu *EMTUpdater) VerifyHash() error {
	fmt.Println("Verify file SHA.")

	// Extract the file name from the URL
	urlParts := strings.Split(tu.request.Url, "/")
	fileName := urlParts[len(urlParts)-1]
	filePath := downloadDir + "/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return err
	}
	defer file.Close()

	// Create a new SHA256 hash
	hash := sha256.New()
	// Copy the file content into the hash
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return err
	}

	// Compute the hash
	computedHash := hash.Sum(nil)

	// Convert the computed hash to a hex string
	computedChecksum := hex.EncodeToString(computedHash)

	if computedChecksum != tu.request.Signature {
		errMsg := fmt.Sprintf("Checksum mismatch. Expected: %s, got: %s", tu.request.Signature, computedChecksum)
		fmt.Println(errMsg)
		return errors.New(errMsg)
	}
	fmt.Println("SHA verification complete.")

	return nil
}

// EMTRebooter is the concrete implementation of the IUpdater interface
// for the EMT OS.
type EMTRebooter struct{}

// Reboot method for EMT
func (tu *EMTRebooter) Reboot() error {
	panic("unimplemented")
}
