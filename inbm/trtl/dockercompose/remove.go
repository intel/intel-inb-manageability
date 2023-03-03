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

// ImageRemoveAll removes all images of a specific name
func ImageRemoveAll(cw util.ExecCommandWrapper, instanceName string) error {
	fmt.Fprint(os.Stdout, "ImageRemoveAll for docker-compose")

	args := []string{"down", "--rmi", "all"}
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error removing images using docker-compose: %s", err)
	}

	return err
}
