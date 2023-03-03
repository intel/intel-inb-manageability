/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"

	"github.com/docker/docker/api/types/container"
	"os"
	"iotg-inb/trtl/logging"
	"iotg-inb/trtl/util"
)

// Instantiate ensures at least one container corresponding to the Instance exists.
// If there is a corresponding image, but no container, one is created with the specified start command.
// It returns container ID and any encountered error.
func (i Instance) Instantiate(options ContainerOptions, securityOptions []string) (string, error) {
	dw := DockerWrap{}
	df := DockerFinder{}
	containerFound, container, err := df.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return "", err
	}
	if !containerFound {
		return i.createContainer(df, dw, options, securityOptions)
	}
	return container.ID, err
}

func (i Instance) createContainer(f Finder, dw DockerWrapper, options ContainerOptions, securityOptions []string) (string, error) {
	imageID, err := f.FindImage(dw, i.GetImageTag())
	if err != nil {
		return "", err
	}
	if len(imageID) == 0 {
		fmt.Fprintf(os.Stdout, "Image %s not found; pulling.", i.GetImageTag())
		err = ImagePull(f, dw, i.GetImageTag(), "", 180)
		if err != nil {
			return "", err
		}
	}

	logging.DebugLogLn("creating a container...", i.GetImageTag(),
		"- start command is", i.GetStartCommand())
	// no container instance: create one
	hostConfig := container.HostConfig{
		SecurityOpt: securityOptions,
	}

	containerID, err := CreateContainer(dw, i.GetImageTag(), "", i.GetStartCommand(), options, hostConfig)
	if err == nil {
		logging.DebugLogLn("Instantiated a container from image", i.GetImageTag(), ":", containerID)
	} else {
		fmt.Fprintf(os.Stderr, "Error encountered while instantiating new container: %s", err)
	}
	return containerID, err
}

// CreateStartCommand creates the command that is used for executing docker commands.
// It returns the command string.
func CreateStartCommand() []string {
	cmd := make([]string, 1)
	cmd[0] = util.ShellCmd
	return cmd
}
