/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package parser

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"
)

// ConfigFilePath is the location to the TRTL configuration file
const ConfigFilePath = "/etc/trtl.conf"

// Structs that are used to parse the configuration file
type Configuration struct {
	XMLName   xml.Name  `xml:"configuration"`
	Container Container `xml:"container"`
}
type Container struct {
	XMLName                 xml.Name `xml:"container"`
	OverwriteImageOnImport  string   `xml:"overwriteImageOnImport"`
	NumberImagesHeld        string   `xml:"numberImagesHeld"`
	DockerWaitTimeInSeconds string   `xml:"dockerWaitTimeInSeconds"`
}

// ConfigValue specifies which value from the config file to retrieve
type ConfigValue int

const (
	// OverwriteImageOnImport the flag to check whether to overwrite an image or not.
	OverwriteImageOnImport ConfigValue = iota
	// NumberImagesHeld is the number of images to keep.
	NumberImagesHeld
	// DockerWaitTimeInSeconds is the number of seconds to wait
	// for any long running docker command to complete before failing.
	DockerWaitTimeInSeconds
)

// ParseConfigValue retrieves the current value for a given configuration setting
// It returns the current value if successfully retrieved, or otherwise an error message
func ParseConfigValue(filePath string, value ConfigValue) (string, error) {
	// Since the configuration path is coming from a constant within the program and not from the user, we just
	// need to check that the path wasn't redirected as a symlink.  We don't need to canonicolize it.
	fi, err := os.Lstat(filePath)
	if err != nil {
		return "", fmt.Errorf("unable to get file information from configuration file")
	}

	if fi.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("configuration file is pointing to a symlink which is not allowed")
	}

	file, err := os.Open(filePath)

	if err != nil {
		return "", fmt.Errorf("unable to open TRTL Configuration file: %s", err)
	}

	defer func() {
		if err = file.Close(); err != nil {
			log.Fatalf("Error closing standard input from docker pull:%s", err)
		}
	}()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return "", errors.Wrap(err, "unable to read XML file.")
	}

	var config Configuration
	err = xml.Unmarshal(bytes, &config)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse XML file.")
	}

	configValue := ""
	switch value {
	case OverwriteImageOnImport:
		configValue = config.Container.OverwriteImageOnImport
	case NumberImagesHeld:
		configValue = config.Container.NumberImagesHeld
	case DockerWaitTimeInSeconds:
		configValue = config.Container.DockerWaitTimeInSeconds
	}

	return configValue, nil
}
