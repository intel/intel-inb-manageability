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

// ImageRemoveAll removes all images of a specific name
func ImageRemoveAll(cw util.ExecCommandWrapper, instanceName string) error {
	fmt.Fprint(os.Stdout, "ImageRemoveAll for docker-compose")

	args := []string{"down", "--rmi", "all"}
	dir := dockerComposeDir + "/" + instanceName
	cmdOut, err := cw.CombinedOutput(dockerComposeCmd, dir, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", cmdOut)
		fmt.Fprintf(os.Stderr, "Error removing images using docker-compose: %s", err)
	}

	return err
}
