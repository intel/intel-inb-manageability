/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides calls to docker
package realdocker

import (
	"github.com/docker/docker/api/types/container"
)

// GetContainerState gets the state of the specified container by ID.
// It returns the container state and any error encountered.
func GetContainerState(dw DockerWrapper, containerID string) (container.State, error) {
	var containerState container.State
	containerJSON, err := dw.ContainerInspect(containerID)
	if err != nil {
		return containerState, err
	}

	return *containerJSON.State, nil
}

// GetImageByContainerId get the image id and image name for the specified containerID
// It returns the image id and image name any error encountered.
func GetImageByContainerId(dw DockerWrapper, containerID string) (string, string, error) {
	containerJSON, err := dw.ContainerInspect(containerID)
	if err != nil {
		return "", "", err
	}
	return containerJSON.Image, containerJSON.Config.Image, nil
}
