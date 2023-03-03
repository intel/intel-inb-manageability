/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"github.com/spf13/afero"
	"os"
	"iotg-inb/trtl/util"
)

// Load will load an image from the tar ball specified
// path is the the location where the tar ball is located
func Load(f Finder, dw DockerWrapper, path string, ref string, maxSeconds int) error {
	fh, err := util.OpenFile(path, afero.NewOsFs()) // File handle automatically closed by ImageLoad.
	if err != nil {
		return err
	}

	err = dw.ImageLoad(fh, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the image '%s': %s", path, err)
		return err
	}

	return waitForImage(f, dw, maxSeconds, ref)
}
