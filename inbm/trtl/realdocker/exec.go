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
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
)

// Exec executes a given command on a given container ID, copying container stdout and stderr
// to os.Stdout.
// It returns any error encountered.
func Exec(dw DockerWrapper, containerID string, cmd []string) error {
	if len(cmd) == 0 {
		return errors.New("no command provided")
	}
	
	execConfig := container.ExecOptions{
		Cmd:          cmd,
		Detach:       false,
		AttachStdout: true,
		AttachStderr: true}

	execObject, err := dw.ContainerExecCreate(containerID, execConfig)
	if err != nil {
		return err
	}

	err = dw.ContainerExecAttach(execObject.ID, container.ExecStartOptions{Detach: false})
	if err != nil {
		return fmt.Errorf("failed to attach to exec instance: %w", err)
	}
	return nil
}

// Exec corresponds to the docker exec command.  It executes a given command in a given instance and version.
// If options string has an execCommand then the cmd executed will be overwritten with this string.  Either execCommand
// or the options parameter are required.
func (i Instance) Exec(f Finder, dw DockerWrapper, cmd []string, options ContainerOptions, securityOptions []string) error {
	found, containerInfo, err := f.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return err
	}

	containerID := containerInfo.ID
	if !found {
		hostConfig := container.HostConfig{
			SecurityOpt: securityOptions,
		}

		containerID, err = CreateContainer(dw, i.GetImageTag(), "", i.GetStartCommand(), options,
			hostConfig)
		if err != nil {
			return err
		}
		err = StartContainer(dw, containerID)
		if err != nil {
			return err
		}
	}

	running, err := IsRunning(dw, containerID)
	if err != nil {
		return err
	}

	if !running {
		if err := StartContainer(dw, containerID); err != nil {
			return err
		}
	}

	if len(options.Execcmd) > 0 {
		cmd = append(strings.Fields(options.Execcmd))
	}

	return Exec(dw, containerID, cmd)
}
