/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package btrfs

import (
	"fmt"
	"iotg-inb/trtl/util"
	"os"
	"strconv"
)

// DeleteSnapshot will use Snapper to delete the specified snapshot number.
func DeleteSnapshot(cw util.ExecCommandWrapper, configName string, snapshotNumber int) error {
	args := []string{"-c", configName, "delete", strconv.Itoa(snapshotNumber)}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error deleting snapshot using Snapper: %s", err)
		return err
	}

	return nil
}

// DeleteConfig will use Snapper to delete the configuration for a filesystem and subvolume.
func DeleteConfig(cw util.ExecCommandWrapper, configName string) error {
	args := []string{"-c", configName, "delete-config"}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error deleting configuration using Snapper: %s", err)
		return err
	}

	return nil
}
