/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

package dockercompose

import (
	"fmt"
	"iotg-inb/trtl/util"
	"os"
)

var dockerComposeDir = "/var/cache/manageability/dispatcher-docker-compose"
var dockerComposeCmd = "docker-compose"
var dockerCmd = "docker"

var unTar = util.UnTar

// UpWithFile builds, (re)creates, starts, and attaches to containers for a service.  This takes an additional YML filename
func UpWithFile(cw util.ExecCommandWrapper, instanceName string, fileName string) error {
	args := []string{"-f", fileName, "up", "-d", "--build"}
	return composeUp(cw, instanceName, args)
}

// Up builds, (re)creates, starts, and attaches to containers for a service
func Up(cw util.ExecCommandWrapper, instanceName string) error {
	args := []string{"up", "-d", "--build"}
	return composeUp(cw, instanceName, args)
}

func composeUp(cw util.ExecCommandWrapper, instanceName string, args []string) error {
	if err := unTar(cw, instanceName, dockerComposeDir); err != nil {
		return err
	}
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error starting container using docker-compose: %s", err)
	}
	return err
}
