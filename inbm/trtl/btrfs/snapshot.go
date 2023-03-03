/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package btrfs

import (
	"errors"
	"fmt"
	"iotg-inb/trtl/util"
	"os"
	"os/exec"
	"strings"
)

var execCommand = exec.Command
var isSnapper = isSnapperOnSystem

// SingleSnapshot will use Snapper to create a single snapshot of the sub volume configured in the
// given config file.
func SingleSnapshot(cw util.ExecCommandWrapper, configName string, desc string) error {
	if !isSnapper(cw) {
		return errors.New("snapper does not exist on the system.  Please install and try again")
	}

	var (
		cmdOut []byte
		err    error
	)

	if err = pConfig(cw, configName); err != nil {
		return err
	}

	args := []string{"-c", configName, "create", "-p", "--description", desc}

	if cmdOut, err = cw.CombinedOutput(snapper, "", args, isDockerApp()); err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error creating single snapshot using snapper: %s", err)
		return err
	}

	fmt.Println(strings.Replace(string(cmdOut), "\n", "", -1))
	return nil
}
