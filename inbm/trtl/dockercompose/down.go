/*
    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package dockercompose

import (
	"fmt"
	"os"
	"iotg-inb/trtl/util"
)

// Stop stops a running container matching the specified image name and version
func Down(cw util.ExecCommandWrapper, instanceName string) error {
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, []string{"down"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error stopping and removing containers using docker-compose: %s", err)
	}

	return err
}


// Stop stops a running container matching the specified image name and version
func DownWithFile(cw util.ExecCommandWrapper, instanceName string, fileName string) error {
	args := []string{"-f", fileName, "down"}
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error stopping and removing containers using docker-compose: %s", err)
	}

	return err
}