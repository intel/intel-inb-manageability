/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides calls to docker
package realdocker

import (
	"errors"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
)

// IsRunning finds out whether a given container (by ID) is running.
// It returns true if running; else false.  It returns any error encountered.
func IsRunning(dw DockerWrapper, containerID string) (bool, error) {
	json, err := dw.ContainerInspect(containerID)
	if err != nil {
		return false, err
	}

	return json.State.Running, nil
}

// GetLatestImageVersionNumber retrieves the latest version number of the given image name.
// It returns whether it found the image, the latest image version number, and any error encountered.
func GetLatestImageVersionNumber(dw DockerWrapper, image string) (bool, int, error) {
	args := filters.NewArgs()
	args.Add("reference", image)

	images, err := dw.ImageList(types.ImageListOptions{All: false, Filters: args})
	if err != nil {
		return false, 0, err
	}

	if len(images) == 0 {
		return false, 0, errors.New("image name does not exist")
	}

	latest := findLatestImage(images)
	return true, latest, nil
}

func findLatestImage(images []types.ImageSummary) int {
	l := 0
	for _, image := range images {
		s := strings.Split(image.RepoTags[0], ":")
		tag, err := strconv.Atoi(s[len(s)-1])
		if err == nil {
			if tag > l {
				l = tag
			}
		}
	}
	return l
}

type byDate []types.Container

func (s byDate) Len() int {
	return len(s)
}

func (s byDate) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byDate) Less(i, j int) bool {
	return s[i].Created < s[j].Created
}

// StartContainer starts a container of the given ID.
// It returns any error encountered.
func StartContainer(dw DockerWrapper, containerID string) error {
	return dw.ContainerStart(containerID, types.ContainerStartOptions{})
}
