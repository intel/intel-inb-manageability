/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	util "github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/spf13/afero"
	"golang.org/x/sys/unix"
)

var (
	configFilePath = "/etc/intel_manageability.conf"
	JWTTokenPath   = "/etc/intel_edge_node/tokens/release-service/access_token"
	DownloadDir    = "/var/cache/manageability/repository-tool/sota"
)

// EMTDownloader is the concrete implementation of the IDownloader interface
// for the EMT OS.
type Downloader struct {
	request                 *pb.UpdateSystemSoftwareRequest
	readJWTTokenFunc        func(afero.Afero, string) (string, error)
	writeUpdateStatus       func(string, string, string)
	writeGranularLog        func(string, string)
	statfs                  func(string, *unix.Statfs_t) error
	httpClient              *http.Client
	requestCreator          func(string, string, io.Reader) (*http.Request, error)
	fs                      afero.Fs
	getFreeDiskSpaceInBytes func(string) (uint64, error)
	getFileSizeInBytesFunc  func(string, string) (int64, error)
}

// NewDownloader creates a new Downloader.
func NewDownloader(request *pb.UpdateSystemSoftwareRequest) *Downloader {
	return &Downloader{
		request:                 request,
		readJWTTokenFunc:        readJWTToken,
		writeUpdateStatus:       writeUpdateStatus,
		writeGranularLog:        writeGranularLog,
		statfs:                  unix.Statfs,
		httpClient:              &http.Client{},
		requestCreator:          http.NewRequest,
		fs:                      afero.NewOsFs(),
		getFreeDiskSpaceInBytes: util.GetFreeDiskSpaceInBytes,
		getFileSizeInBytesFunc:  getFileSizeInBytes,
	}
}

// Download implements IDownloader.
func (t *Downloader) Download() error {
	config, err := LoadConfig(t.fs, configFilePath)
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	// Get the request details
	jsonString, err := protojson.Marshal(t.request)
	if err != nil {
		log.Printf("Error converting request to string: %v\n", err)
		jsonString = []byte("{}")
	}

	// Perform source verification
	if !IsTrustedRepository(t.request.Url, config) {
		errMsg := fmt.Sprintf("URL '%s' is not in the list of trusted repositories.", t.request.Url)
		t.writeUpdateStatus(FAIL, string(jsonString), errMsg)
		t.writeGranularLog(FAIL, FAILURE_REASON_RS_AUTHENTICATION)
		return errors.New(errMsg)
	}

	log.Println("Downloading update from", t.request.Url)

	// Check available space on disk
	isDiskEnough, err := t.isDiskSpaceAvailable()
	if err != nil {
		return fmt.Errorf("error checking disk space: %w", err)
	}

	if !isDiskEnough {
		t.writeUpdateStatus(FAIL, string(jsonString), "Insufficient disk space")
		t.writeGranularLog(FAIL, FAILURE_REASON_INSUFFICIENT_STORAGE)
		return fmt.Errorf("insufficient disk space")
	}

	log.Println("Sufficient disk space available. Proceeding to download the artifact.")

	// Download file
	err = t.downloadFile()
	if err != nil {
		t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
		t.writeGranularLog(FAIL, FAILURE_REASON_DOWNLOAD)
		return fmt.Errorf("error downloading the file: %w", err)
	}

	log.Println("Download complete.")

	return nil
}

// VerifyHash verifies the hash of the downloaded file.
func (t *EMTUpdater) VerifyHash() error {
	log.Println("Verify file SHA.")

	// Extract the file name from the URL
	urlParts := strings.Split(t.request.Url, "/")
	fileName := urlParts[len(urlParts)-1]
	filePath := DownloadDir + "/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Create a new SHA256 hash
	hash := sha256.New()
	// Copy the file content into the hash
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Compute the hash
	computedHash := hash.Sum(nil)

	// Convert the computed hash to a hex string
	computedChecksum := hex.EncodeToString(computedHash)

	if computedChecksum != t.request.Signature {
		return fmt.Errorf("checksum mismatch: Expected: %s, got: %s", t.request.Signature, computedChecksum)
	}
	log.Println("SHA verification complete.")

	return nil
}

// downloadFile downloads the file from the url.
func (t *Downloader) downloadFile() error {
	// Create a new HTTP request
	req, err := t.requestCreator("GET", t.request.Url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Add the JWT token to the request header
	token, err := t.readJWTTokenFunc(afero.Afero{Fs: t.fs}, JWTTokenPath)
	if err != nil {
		return fmt.Errorf("error reading JWT token: %w", err)
	}

	// Check if the token exists
	if token == "" {
		log.Println("JWT token is empty. Proceeding without Authorization.")
	} else {
		// Add the JWT token to the request header
		req.Header.Add("Authorization", "Bearer "+token)
	}

	// Perform the request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error performing request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the status code is 200/Success. If not, return the error.
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Status code: %d. Expected 200/Success.", resp.StatusCode)
		return errors.New(errMsg)
	}

	// Extract the file name from the URL
	urlParts := strings.Split(t.request.Url, "/")
	fileName := urlParts[len(urlParts)-1]

	// Create the file
	file, err := t.fs.Create(DownloadDir + "/" + fileName)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	// Copy the response body to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}

	return nil
}

// readJWTToken reads the JWT token that is used for accessing RS server.
func readJWTToken(fs afero.Afero, path string) (string, error) {
	file, err := fs.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	token, err := afero.ReadFile(fs, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

// isDiskSpaceAvailable checks if there is enough disk space to download the artifacts.
func (t *Downloader) isDiskSpaceAvailable() (bool, error) {
	availableSpace, err := t.getFreeDiskSpaceInBytes("/var/cache/manageability/repository-tool/sota")
	if err != nil {
		log.Printf("Error getting disk space: %v\n", err)
		return false, err
	}

	// Get the request details
	jsonString, err := protojson.Marshal(t.request)
	if err != nil {
		log.Printf("Error converting request to string: %v\n", err)
		jsonString = []byte("{}")
	}

	// Read JWT token
	token, err := t.readJWTTokenFunc(afero.Afero{Fs: t.fs}, JWTTokenPath)
	if err != nil {
		t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
		t.writeGranularLog(FAIL, FAILURE_REASON_INBM)
		return false, fmt.Errorf("error reading JWT token: %w", err)
	}
	log.Println("JWT token read successfully.")

	requiredSpace, err := t.getFileSizeInBytesFunc(t.request.Url, token)
	if err != nil {
		t.writeUpdateStatus(FAIL, string(jsonString), err.Error())
		t.writeGranularLog(FAIL, FAILURE_REASON_DOWNLOAD)
		return false, fmt.Errorf("error getting file size: %w", err)
	}

	// Check if there is enough space
	if availableSpace < uint64(requiredSpace) {
		log.Printf("Insufficient disk space. Available: %d bytes, Required: %d bytes\n", availableSpace, requiredSpace)
		return false, nil
	}

	return true, nil
}

func getFileSizeInBytes(url string, token string) (int64, error) {
	// Create a new HTTP GET request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating GET request: %w", err)
	}
	log.Println("Created GET request for URL:", url)

	// Add the JWT token to the request header if it exists
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
		log.Println("Added JWT token to GET request header.")
	} else {
		log.Println("JWT token is empty. Proceeding without Authorization.")
	}

	// Perform the GET request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error performing GET request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the status code is 200/Success
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET request failed with status code: %d", resp.StatusCode)
	}

	// Get the Content-Length header
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		return 0, fmt.Errorf("Content-Length header is missing in GET response")
	}

	// Parse the Content-Length to an integer
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing Content-Length: %w", err)
	}

	return size, nil
}
