/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package btrfs

import (
	"fmt"
	"iotg-inb/trtl/util"
	"os"
)

const unknownConfig = "Unknown config.\n"
const snapper = "snapper"

var cConfig = createConfig
var pConfig = prepareConfig
var dList = setDefaultHelper

// isDockerApp checks if trtl is running in a container
// Returns true if trtl is running in a container
func isDockerApp() bool {
	if os.Getenv("container") == "" {
		return false
	}
	return true
}

// prepareConfig checks to see if a configuration file already exists for Snapper.  If it does not, it will create it.
// Returns an error if it is unable to find or create the configuration file.
func prepareConfig(cw util.ExecCommandWrapper, configName string) error {
	exist, err := isConfigExist(cw, configName)
	if err != nil {
		return err
	}
	if !exist {
		if err = cConfig(cw, configName); err != nil {
			return err
		}
		return dList(cw, configName)
	}
	return nil
}

// isConfigExist will use the snapper command get-config to check if the provided configName exists.
// Sends back an error if the configuration file does not exist.
func isConfigExist(cw util.ExecCommandWrapper, configName string) (bool, error) {
	args := []string{"-c", configName, "get-config"}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		if string(cmdOut) == unknownConfig {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// setDefaultHelper loops the various configuration items defined in the array and sets them one item at a time
// using the setDefaultConfig function
func setDefaultHelper(cw util.ExecCommandWrapper, configName string) error {
	a := []string{"BACKGROUND_COMPARISON=no", "NUMBER_CLEANUP=no", "TIMELINE_CREATE=no", "TIMELINE_CLEANUP=no", "EMPTY_PRE_POST_CLEANUP=no"}
	for i := 0; i < len(a); i++ {
		if err := setDefaultConfig(cw, configName, a[i]); err != nil {
			return err
		}
	}
	return nil
}

// setDefaultConfig configures the configuration one key-value at a time for the mentioned Configname
func setDefaultConfig(cw util.ExecCommandWrapper, configName string, configItem string) error {
	args := []string{"-c", configName, "set-config", configItem}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		if len(string(cmdOut)) > 0 {
			return err
		}
	}
	return nil
}

// createConfig creates a configuration file using the '/' subvolume.
// Uses the configName provided.
func createConfig(cw util.ExecCommandWrapper, configName string) error {
	args := []string{"-c", configName, "create-config", "/"}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error creating snapper configuration file: %s", err)
		return err
	}

	return nil
}
