/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"errors"
	"fmt"

	"github.com/docker/docker/api/types"
	"iotg-inb/trtl/logging"
)

// Commit searches for a matching container and commits it to its corresponding
// image tag
// It returns any error encountered.
func (i Instance) Commit(df Finder, dw DockerWrapper) error {
	containerFound, container, err := df.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return err
	}
	if !containerFound {
		return errors.New("Unable to commit changes. Container not found matching " + i.GetImageTag())
	}

	return commitContainer(dw, container.ID, i.GetImageTag(), fmt.Sprintf("commit created by trtl (%s)",
		i.GetImageTag()))
}

func commitContainer(dw DockerWrapper, containerID string, commitTag string, comment string) error {
	containerID, err := CommitContainer(dw, containerID, commitTag, comment)
	if err != nil {
		return err
	}

	logging.DebugLogLn("Commit", containerID, "to", commitTag)

	return nil
}

// CommitContainer commits a container by ID to a given commit tag, with provided comment.
// It returns the commit ID and any error encountered.
func CommitContainer(dw DockerWrapper, containerID string, commitTag string, comment string) (string, error) {
	response, err := dw.ContainerCommit(containerID,
		types.ContainerCommitOptions{
			Comment:   comment,
			Reference: commitTag})
	if err != nil {
		return "", err
	}
	return response.ID, err
}
