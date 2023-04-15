/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/spf13/afero"
	"os"
	"iotg-inb/trtl/util"
)

// CopyToContainer copies and decompresses a tar file from a filesystem to a container.
func CopyToContainer(df Finder, dw DockerWrapper, src string, fileName string, path string) error {
	containerFound, container, err := df.FindContainer(dw, src)
	if err != nil {
		return err
	}
	if !containerFound {
		return errors.New("Unable to copy to container. Container not found matching " + src)
	}

	fh, err := util.OpenFile(fileName, afero.NewOsFs())
	if err != nil {
		return err
	}
	defer util.CloseFile(fh)

	if err := dw.CopyToContainer(container.ID, path, fh, types.CopyToContainerOptions{AllowOverwriteDirWithFile: true}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to copy the file to container '%s': %s", container.ID, err)
		return err
	}

	return nil
}
