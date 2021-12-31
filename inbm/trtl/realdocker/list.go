/*
    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"
	"strconv"
	"strings"

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

// ListContainers list all containers for all images that are either 'latest' or have a tag number.
// It will list the container ID, state, and image name.  It will provide 'NONE' for the container ID
// and state if the image does not have an active container.
// It will return any error encountered.
func ListContainers(dw DockerWrapper) error {
	images, err := dw.ImageList(types.ImageListOptions{All: true})
	if err != nil {
		return err
	}

	fmt.Println("CONTAINERID\t\tSTATE\t\tIMAGE")

	for _, image := range images {
		if len(image.RepoTags) > 0 {
			s := strings.Split(image.RepoTags[0], ":")
			_, err = strconv.ParseInt(s[len(s)-1], 10, 64)
			if s[len(s)-1] != "<none>" || err == nil {
				if err = printImageInformation(dw, image); err != nil {
					return nil
				}
			}

			if s[len(s)-1] == "<none>" {
				err = nil
			}
		}
	}

	return err
}

var printImageInformation = func(dw DockerWrapper, image types.ImageSummary) error {
	containers, err := GetAllContainers(dw, true, image.ID)
	if err != nil {
		return err
	}

	imageTag := strings.TrimSuffix(image.RepoTags[0], ":latest")

	found := false
	for _, container := range containers {
		containerTag := strings.TrimSuffix(container.Image, ":latest")
		if containerTag == imageTag {
			found = true
			fmt.Printf("%s\t\t%s\t\t%s\n", container.ID[:12], container.State, container.Image)
		}
	}

	if len(containers) == 0 || !found {
		fmt.Printf("%s\t\t\t%s\t\t%s\n", "NONE", "NONE", imageTag)
	}
	return nil
}
