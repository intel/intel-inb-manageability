/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

package dockercompose

import (
	"errors"
	"fmt"
	"iotg-inb/trtl/util"
	"os"
)

// Pull pulls the latest changes of all images mentioned in the file
func Pull(cw util.ExecCommandWrapper, instanceName string) error {
	fmt.Fprint(os.Stdout, "ImagePull for docker-compose")
	if instanceName != "" {
		if err := util.UnTar(cw, instanceName, dockerComposeDir); err != nil {
			return err
		}

		args := []string{"pull"}
		dir := dockerComposeDir + "/" + instanceName
		cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", cmdOut)
			fmt.Fprintf(os.Stderr, "Error pulling image using docker-compose: %s", err)
		}

		return err
	} else {
		return errors.New("invalid ImageTag for Docker-compose pull")
	}
}

// Pull pulls the latest changes of all images mentioned in the file
func PullWithFile(cw util.ExecCommandWrapper, instanceName string, fileName string) error {
	fmt.Fprint(os.Stdout, "ImagePull for docker-compose")
	if instanceName != "" {
		if err := util.UnTar(cw, instanceName, dockerComposeDir); err != nil {
			return err
		}

		args := []string{"-f", fileName, "pull"}
		dir := dockerComposeDir + "/" + instanceName
		cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", cmdOut)
			fmt.Fprintf(os.Stderr, "Error pulling image using docker-compose: %s", err)
		}

		return err
	} else {
		return errors.New("invalid ImageTag for Docker-compose pull")
	}
}
