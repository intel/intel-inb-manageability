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

// UndoChange will use Snapper to undo any changes made after the snapshot version.
func UndoChange(cw util.ExecCommandWrapper, configName string, sv int) error {
	var (
		cmdOut []byte
		err    error
	)

	args := []string{"-c", configName, "undochange", strconv.Itoa(sv) + "..0"}

	if cmdOut, err = cw.CombinedOutput(snapper, "", args); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error using Snapper undoChange: %s", err)
		return err
	}

	fmt.Println("Status: ", string(cmdOut))
	return nil
}
