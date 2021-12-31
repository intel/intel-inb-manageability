/*
    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/
package btrfs

import (
	"fmt"
	"os"
	"strconv"
	"iotg-inb/trtl/util"
)

// DeleteSnapshot will use Snapper to delete the specified snapshot number.
func DeleteSnapshot(cw util.ExecCommandWrapper, configName string, snapshotNumber int) error {
	args := []string{"-c", configName, "delete", strconv.Itoa(snapshotNumber)}

	if cmdOut, err := cw.CombinedOutput(snapper, "", args); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error deleting snapshot using Snapper: %s", err)
		return err
	}

	return nil
}
