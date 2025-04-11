/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides calls to the real docker API
package realdocker

import (
	"fmt"
	"sort"
	"strconv"

	"iotg-inb/trtl/logging"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
)

// GetImageTag returns the Docker image tag associated with the Instance
// e.g. -- "hello-world:2"; as special cases, version 0 resolves as e.g. "hello-world:latest" and version -1 resolves as e.g. "hello-world"
func (i Instance) GetImageTag() string {
	ver := i.GetVersion()
	var verString string
	if ver == -1 {
		verString = ""
	}
	if ver == 0 {
		verString = ":latest"
	} else {
		verString = ":" + strconv.Itoa(ver)
	}
	return fmt.Sprintf("%s%s", i.GetName(), verString)
}

// GetImageTagSuccessor returns the Docker image tag associated with the Instance
// except with the version incremented. e.g. -- "hello-world:3"
func (i Instance) GetImageTagSuccessor() string {
	return fmt.Sprintf("%s:%d", i.GetName(), i.GetVersion()+1)
}

// Finder is an interface for all find methods
type Finder interface {
	FindContainer(DockerWrapper, string) (bool, container.Summary, error)
	FindImage(DockerWrapper, string) (string, error)
}

// DockerFinder is the structure used with the Finder interface.
type DockerFinder struct{}

// FindContainer locates the most recently created Docker container associated with a given
// image name.
// It returns whether the container was found, the container, and any error encountered.
func (df DockerFinder) FindContainer(dw DockerWrapper, imageName string) (bool, container.Summary, error) {
	args := filters.NewArgs()
	args.Add("ancestor", imageName)

	containers, err := dw.ContainerList(container.ListOptions{Filters: args, All: true})
	if err != nil {
		return false, container.Summary{}, err
	}

	containersMatchingImage := make([]container.Summary, 0)
	for _, v := range containers {
		if v.Image == imageName {
			containersMatchingImage = append(containersMatchingImage, v)
		}
	}

	if len(containersMatchingImage) == 0 {
		return false, container.Summary{}, nil
	}

	sort.Sort(byDate(containersMatchingImage))
	container := containersMatchingImage[len(containersMatchingImage)-1]

	return true, container, nil
}

// FindImage looks for an image with a given tag,.
// It returns true if it finds the image and any error encountered.
func (df DockerFinder) FindImage(dw DockerWrapper, imageTag string) (string, error) {
	filters := filters.NewArgs()
	filters.Add("reference", imageTag)

	result, err := dw.ImageList(image.ListOptions{Filters: filters})
	if err != nil {
		return "", err 
	}

	if len(result) > 0 {
		logging.DebugLogLn("Found image tag `%s` with ID %s\n", imageTag, result[0].ID)
		return result[0].ID, err
	}

	return "", err
}
