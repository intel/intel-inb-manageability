/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"fmt"
	"os"
)

// UnTar untars a compressed file with extension .tar.gz
// Returns any error encountered
func UnTar(cw ExecCommandWrapper, filename string, dir string) error {
	zipFile := filename + ".tar.gz"
	args := []string{"zxvf", zipFile}
	err := cw.Run("tar", dir, args, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to untar file '%s':%s", zipFile, err)
	}
	return err
}
