/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"errors"

	"github.com/docker/docker/api/types/container"
)

// Logs retrieves logs from target.  Currently can be used by docker or compose.
func Logs(f Finder, dw DockerWrapper, options ContainerLogOptions, target string) error {
	containerFound, containerInfo, err := f.FindContainer(dw, target)
	if err != nil {
		return err
	}

	if !containerFound {
		return errors.New("Docker Container Logs could not find container: " + target)
	}

	o := container.LogsOptions{ShowStderr: true, ShowStdout: true, Timestamps: true}

	if len(options.Details) > 0 {
		o.Details = true
	}

	if len(options.Since) > 0 {
		o.Since = options.Since
	}

	if len(options.Tail) > 0 {
		o.Tail = options.Tail
	}

	return dw.ContainerLogs(o, containerInfo.ID)
}
