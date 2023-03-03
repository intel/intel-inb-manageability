/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"strconv"
	"strings"
	"encoding/json"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
)

// GetAllImagesByName retrieves a list of matching images along with their properties.
// It returns the list of images and any error encountered.
func GetAllImagesByName(dw DockerWrapper, imageName string) ([]types.ImageSummary, error) {
	args := filters.NewArgs()
	if len(imageName) > 0 {
		args.Add("reference", imageName)
	}

	images, err := dw.ImageList(types.ImageListOptions{All: true, Filters: args})
	if err != nil {
		return nil, err
	}

	return images, nil
}

// GetAllContainers retrieves a list of all containers matching the image name.
// It returns the list of containers and any error encountered.
func GetAllContainers(dw DockerWrapper, all bool, imageName string) ([]types.Container, error) {
	args := filters.NewArgs()
	if len(imageName) > 0 {
		args.Add("ancestor", imageName)
	}

	containers, err := dw.ContainerList(types.ContainerListOptions{All: all, Filters: args})
	if err != nil {
		return nil, err
	}

	return containers, nil
}

// ContainerUsage is a structure to hold container usage.
type ContainerInfo struct {
    ImageName string `json:"imageName"`
	ID string `json:"id"`
	State string `json:"state"`
}

// GetAllContainers retrieves a list of all containers on the system in the running state.
// It returns the list of all running container IDs and any error encountered.
func GetAllRunningContainers(dw DockerWrapper) ([]ContainerInfo, error) {
	containers, err := dw.ContainerList(types.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}

	var runningContainers []ContainerInfo
	for _, container := range containers {
        if container.State == "running" {
            runningContainers = append(runningContainers,
							ContainerInfo{ImageName: container.Image, ID: container.ID[:12], State: container.State})
        }
    }
	return runningContainers, nil
}

// AllContainerUsage is a structure to marshal the container usage information in JSON format
type allContainers struct {
	// Containers is a slice of ContainerUsages
	AllContainers []ContainerInfo `json:"containers"`
}

// ListContainers list all containers for all images that are either 'latest' or have a tag number.
// It will list the container ID, state, and image name.  It will provide 'NONE' for the container ID
// and state if the image does not have an active container.
// It will return any error encountered.
func ListContainers(dw DockerWrapper, imageName string) error {
    var images []types.ImageSummary
    var err error

    if len(imageName) == 0 {
        images, err = dw.ImageList(types.ImageListOptions{All: true})
    } else {
        filters := filters.NewArgs()
        filters.Add("reference", imageName)
        images, err = dw.ImageList(types.ImageListOptions{All: false, Filters: filters})
    }

    if err != nil {
        return err
    }

    var containers []ContainerInfo
		for _, image := range images {
			if len(image.RepoTags) > 0 {
				s := strings.Split(image.RepoTags[0], ":")
				_, err = strconv.ParseInt(s[len(s)-1], 10, 64)
				if s[len(s)-1] != "<none>" || err == nil {
					imageContainers, err := appendImageInformation(dw, image)
					if err == nil {
						containers = append(containers, imageContainers...)
					}
				}

				if s[len(s) - 1] == "<none>" {
					err = nil
				}
		}
	}

	output, err := createContainerListJSON(containers)
	if err != nil {
	    return err
	}
	fmt.Println("ContainerList=", output)
	return nil
}

var appendImageInformation = func(dw DockerWrapper, image types.ImageSummary) ([]ContainerInfo, error) {
	var imageContainers []ContainerInfo

	allContainers, err := GetAllContainers(dw, true, image.ID)
	if err != nil {
		return imageContainers, err
	}

	imageTag := strings.TrimSuffix(image.RepoTags[0], ":latest")
	found := false
	for _, container := range allContainers {
		containerTag := strings.TrimSuffix(container.Image, ":latest")
		if containerTag == imageTag && container.State != "exited" {
			found = true
			imageContainers = append(imageContainers, ContainerInfo{ImageName: container.Image, ID: container.ID[:12], State: container.State})
		}
	}

	if len(allContainers) == 0 || !found {
		imageContainers = append(imageContainers, ContainerInfo{ImageName: imageTag, ID: "NONE", State: "NONE"})
	}

	return imageContainers, nil
}

func createContainerListJSON(containers []ContainerInfo) (string, error) {
    if len(containers) == 0 {
        return "no containers found.", nil
    }

    c := &allContainers{
		AllContainers: containers}
	j, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(j), nil
}
