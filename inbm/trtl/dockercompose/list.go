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

// List lists all the running containers of a specific image name
func List(cw util.ExecCommandWrapper, instanceName string) error {
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, []string{"ps"}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing image using docker-compose: %s", err)
	} else {
		fmt.Fprintf(os.Stdout, "%s", cmdOut)
	}

	return err
}
