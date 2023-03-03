/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"iotg-inb/trtl/logging"
)

func start(f Finder, dw DockerWrapper, options ContainerOptions, securityOptions []string, imageTag string) (containerID string, err error) {
	containerFound, containerInfo, err := f.FindContainer(dw, imageTag)
	if err != nil {
		return "", err
	}
	containerID = containerInfo.ID
	if !containerFound {
		str := strings.Replace(imageTag, ":", "_", -1)

		str = strings.Replace(str, "/", "_", -1) + "_" +
			time.Now().Format("2006-01-02_15-04-05")

		hostConfig := container.HostConfig{
			SecurityOpt: securityOptions,
		}

		containerID, err = CreateContainer(dw, imageTag, str, nil, options, hostConfig) // try instantiating the container, if needed
		if err != nil {
			return "", err
		}
	}

	logging.DebugLogLn("Starting container", containerID, "...")
	err = StartContainer(dw, containerID)
	if err == nil {
		fmt.Println("Started " + imageTag)
	}

	isRunning, err := IsRunning(dw, containerID)
	if !isRunning || err != nil {
		return "", errors.New("container is not in the running state following start")
	}

	return containerID, err
}

// Start starts the instance.
// It returns the containerID and any errors encountered.
func (i Instance) Start(f Finder, dw DockerWrapper, options ContainerOptions, securityOptions []string) (containerID string, err error) {
	return start(f, dw, options, securityOptions, i.GetImageTag())
}

// Start start the image in a container using the image and tag provided
// It returns the containerID and any errors encountered.
func Start(f Finder, dw DockerWrapper, options ContainerOptions, securityOptions []string, imageTag string) (containerID string, err error) {
	return start(f, dw, options, securityOptions, imageTag)
}
