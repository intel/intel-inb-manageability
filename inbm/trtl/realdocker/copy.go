/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides calls to the real docker API
package realdocker

import (
	"fmt"
	"iotg-inb/trtl/util"

	"github.com/docker/docker/api/types/container"
	"github.com/spf13/afero"
)

// CopyToContainer copies and decompresses a tar file from a filesystem to a container.
func CopyToContainer(df Finder, dw DockerWrapper, src string, fileName string, path string) error {
	containerFound, containerInfo, err := df.FindContainer(dw, src)
	if err != nil {
		return err
	}
	if !containerFound {
		return fmt.Errorf("unable to copy to container. Container not found matching '%s'", src)
	}

	fh, err := util.OpenFile(fileName, afero.NewOsFs())
	if err != nil {
		return err
	}
	defer util.CloseFile(fh)

	if err := dw.CopyToContainer(containerInfo.ID, path, fh, container.CopyToContainerOptions{AllowOverwriteDirWithFile: true}); err != nil {
		return fmt.Errorf("failed to copy the file to container '%s': %s", containerInfo.ID, err)
	}

	return nil
}
