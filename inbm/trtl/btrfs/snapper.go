/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package btrfs

import (
	"iotg-inb/trtl/util"
)

// isSnapperOnSystem checks to see if snapper is on the system.
// Returns true if snapper exists; otherwise, false.
func isSnapperOnSystem(cw util.ExecCommandWrapper) bool {
	if err := cw.Run(snapper, "", []string{"--help"}, isDockerApp()); err != nil {
		return false
	}

	return true
}
