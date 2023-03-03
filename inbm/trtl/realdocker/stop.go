/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"os"
	"time"
)

const maxWaitTimeToStopContainer = 20

// StopAll will stop all running containers.
// It will return any error encountered.
func StopAll(dw DockerWrapper, imageName string) error {
	if len(imageName) > 0 {
		images, err := GetAllImagesByName(dw, imageName)
		if err != nil {
			return err
		}

		for _, image := range images {
			if err := getContainersAndStop(dw, image.RepoTags[0]); err != nil {
				return err
			}
		}
	} else {
		if err := getContainersAndStop(dw, imageName); err != nil {
			return err
		}
	}
	return nil
}

func getContainersAndStop(dw DockerWrapper, image string) error {
	containers, err := GetAllContainers(dw, true, image)
	if err != nil {
		return err
	}

	for _, container := range containers {
		if container.State == "running" {
			if err = StopContainer(dw, container.ID); err != nil {
				fmt.Fprintf(os.Stderr, "Error stopping container '%s': %s", container.ID, err)
				return err
			}
		}
	}
	return nil
}

// StopContainer stops a container by containerID.
// It returns any error encountered.
func StopContainer(dw DockerWrapper, containerID string) error {
	fmt.Println("Stopping container", containerID, "...")
	timeout := maxWaitTimeToStopContainer * time.Second
	if err := dw.ContainerStop(containerID, &timeout); err != nil {
		return err
	}

	fmt.Println("Stopped containerID=" + containerID)
	return nil
}

// Stop stops the most recently created docker container with the given image name.
// It returns any error encountered.
func Stop(f Finder, dw DockerWrapper, image string) error {
	fmt.Println("Image to be stopped is: " + image)
	containerFound, container, err := f.FindContainer(dw, image)

	if err != nil {
		return err
	}

	if !containerFound {
		return fmt.Errorf("unable to find container with image '%s'", image)
	}

	if err = StopContainer(dw, container.ID); err != nil {
		return err
	}

	return nil
}
