/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"fmt"
	"iotg-inb/trtl/util"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/spf13/afero"
)

// CopyToContainer copies and decompresses a tar file from a filesystem to a container.
func CopyToContainer(df Finder, dw DockerWrapper, src string, fileName string, path string) error {
	containerFound, containerInfo, err := df.FindContainer(dw, src)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}
	if !containerFound {
		return fmt.Errorf("unable to copy to container. no container found matching %s", src)
	}

	fh, err := util.OpenFile(fileName, afero.NewOsFs())
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", fileName, err)
	}
	defer util.CloseFile(fh)

	if err := dw.CopyToContainer(containerInfo.ID, path, fh, container.CopyToContainerOptions{AllowOverwriteDirWithFile: true}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to copy the file to container '%s': %s", containerInfo.ID, err)
		return err
	}

	return nil
}
