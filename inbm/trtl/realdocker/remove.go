/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"sort"

	"github.com/docker/docker/api/types"
	"os"
)

// RemoveAllContainers will remove all containers.  Running containers will also be removed if force parameter is true.
// It will return any error encountered.
func RemoveAllContainers(dw DockerWrapper, imageName string, force bool) error {
	if len(imageName) > 0 {
		images, err := GetAllImagesByName(dw, imageName)
		if err != nil {
			return err
		}

		if len(images) == 0 {
			return fmt.Errorf("unable to find any images named '%s'", imageName)
		}

		for _, image := range images {
			if err := getContainersAndRemove(dw, image.RepoTags[0], force); err != nil {
				return err
			}
		}
	} else {
		if err := getContainersAndRemove(dw, imageName, force); err != nil {
			return err
		}
	}

	return nil
}

func getContainersAndRemove(dw DockerWrapper, image string, includeRunning bool) error {
	containers, err := GetAllContainers(dw, true, image)
	if err != nil {
		return err
	}

	for _, container := range containers {
		if err = RemoveContainer(dw, container.ID, includeRunning); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing container '%s': %s", container.ID, err)
			return err
		}
	}

	return nil
}

// RemoveContainer removes the container of the specified containerID.  It can optionally force the removal of a running container.
// It returns any error encountered.
func RemoveContainer(dw DockerWrapper, containerID string, force bool) error {
	if !force {
		err := warnIfRunningContainer(dw, containerID)
		if err != nil {
			return err
		}
	}

	fmt.Println("Removing container", containerID, "...")
	if err := dw.ContainerRemove(containerID,
		types.ContainerRemoveOptions{RemoveVolumes: true, Force: force}); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Removed containerID=%s", containerID)
	return nil
}

var warnIfRunningContainer = func(dw DockerWrapper, containerID string) error {
	containerState, err := GetContainerState(dw, containerID)
	if err != nil {
		return err
	}

	if containerState.Running {
		// if force is turned off and container is running, don't remove container.
		fmt.Fprintf(os.Stderr, "Container '%s' is running.  It either needs to be stopped or use the "+
			"-f=true option to force the removal.", containerID)
	}

	return nil
}

// RemoveLatestContainerFromImage removes the most recently created docker container with the given image name.
// It returns any error encountered.
func RemoveLatestContainerFromImage(f Finder, dw DockerWrapper, image string, force bool) error {
	containerFound, container, err := f.FindContainer(dw, image)
	if err != nil {
		return err
	}
	if !containerFound {
		return fmt.Errorf("unable to find container with image '%s'", image)
	}

	if err = RemoveContainer(dw, container.ID, force); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Removed image=%s", image)
	return nil
}

// RemoveImage removes the image of the specified ID.  If the image has an active container, then
// an error will appear unless force=true.
// It will return any error encountered.
func RemoveImage(dw DockerWrapper, imageID string, force bool) error {
	fmt.Println("Removing image", imageID, "...")
	err := dw.ImageRemove(imageID, types.ImageRemoveOptions{PruneChildren: true, Force: force})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Removed imageID=%s", imageID)
	return nil
}

// RemoveAllImages will remove all images on the system if any imageName is not specified.
// If an image name is specified, then all images matching that name will be removed.
// If an image has a container active, then it will not be removed unless force=true.
// It will return any error encountered.
func RemoveAllImages(dw DockerWrapper, imageName string, force bool) error {
	images, err := GetAllImagesByName(dw, imageName)
	if err != nil {
		return err
	}

	if len(images) == 0 {
		return fmt.Errorf("unable to find images named '%s'", imageName)
	}

	sortedImages := sortImages(images)
	for _, image := range sortedImages {
		if err := RemoveImage(dw, image, force); err != nil {
			return err
		}
	}
	return nil
}

func sortImages(images []types.ImageSummary) []string {
	var sortedImageString []string
	for _, image := range images {
		sortedImageString = append(sortedImageString, image.RepoTags[0])
	}

	sort.Sort(sort.Reverse(sort.StringSlice(sortedImageString)))
	return sortedImageString
}
