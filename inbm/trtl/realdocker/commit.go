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

	"iotg-inb/trtl/logging"

	"github.com/docker/docker/api/types/container"
)

// Commit searches for a matching container and commits it to its corresponding
// image tag
// It returns any error encountered.
func (i Instance) Commit(df Finder, dw DockerWrapper) error {
	containerFound, container, err := df.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return fmt.Errorf("unable to find container: %w", err)
	}
	if !containerFound {
		return fmt.Errorf("Unable to commit changes. Container not found matching " + i.GetImageTag())
	}

	return commitContainer(dw, container.ID, i.GetImageTag(), fmt.Sprintf("commit created by trtl (%s)",
		i.GetImageTag()))
}

func commitContainer(dw DockerWrapper, containerID string, commitTag string, comment string) error {
	containerID, err := CommitContainer(dw, containerID, commitTag, comment)
	if err != nil {
		return fmt.Errorf("failed to commit container %s: %w", containerID, err)
	}

	logging.DebugLogLn("Commit", containerID, "to", commitTag)

	return nil
}

// CommitContainer commits a container by ID to a given commit tag, with provided comment.
// It returns the commit ID and any error encountered.
func CommitContainer(dw DockerWrapper, containerID string, commitTag string, comment string) (string, error) {
	if containerID == "" || commitTag == "" {
		return "", errors.New("container ID and commit tag must not be empty")
	}
	if len(comment) > 255 {
		return "", errors.New("comment must not exceed 255 characters")
	}

	opts := container.CommitOptions{
		Comment:   comment,
		Reference: commitTag,
	}
	response, err := dw.ContainerCommit(containerID, opts)
	if err != nil {
		return "", fmt.Errorf("failed to commit container %s to %s: %w", containerID, commitTag, err)
	}
	return response.ID, err
}
