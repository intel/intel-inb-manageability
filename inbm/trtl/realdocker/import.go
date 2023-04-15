/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"os"
)

var osExit = os.Exit

// ImageImport will import the contents from a tarball to create a filesystem image.
// refString is the imagename:tag to associate to the new image, source is the URL of the source
// image, maxWaitSeconds is the number of seconds to wait for image to import.
// overwriteImageFlag is the value that tells whether we should overwrite an image already present or not.
func ImageImport(f Finder, dw DockerWrapper, ref string, src string, maxSeconds int, overwriteImageFlag bool) error {
	if checkCanImport(f, dw, ref, overwriteImageFlag) {
		changes := make([]string, 0)
		err := dw.ImageImport(src, ref, changes)
		if err != nil {
			return err
		}

		return waitForImage(f, dw, maxSeconds, ref)
	}
	osExit(2)
	return nil
}

func checkCanImport(f Finder, dw DockerWrapper, imageName string, overwriteImageFlag bool) bool {
	if overwriteImageFlag {
		return true
	}

	imageID, err := f.FindImage(dw, imageName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in searching for the image '%s': %s", imageName, err)
		return false
	}

	if len(imageID) > 0 && !overwriteImageFlag {
		return false
	}

	return true
}
