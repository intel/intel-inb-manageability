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

// Logs retrieves the log output from docker-compose
// options are the command line options that can be used with docker-compose logs
// target is an optional service.  If not provided all services will be sent.
func Logs(cw util.ExecCommandWrapper, options string, instanceName string, target string) error {
	args := []string{"logs", "-t"}
	if len(options) > 0 {
		args = append(args, options)
	}

	if len(target) > 0 {
		args = append(args, target)
	}

	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error logging container using docker-compose: %s", err)
	}

	fmt.Println(string(cmdOut))
	return err
}
