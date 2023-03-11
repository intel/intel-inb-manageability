/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"fmt"

	"os"
	"iotg-inb/trtl/logging"
)

// Snapshot creates and commits a new Instance with an incremented version.
// It returns the new Instance and any error encountered.
func (i Instance) Snapshot(f Finder, dw DockerWrapper) (Instance, error) {
	logging.DebugLogLn("Snapshotting: ", i.GetVersion(), i.GetName(), nil)
	newInstance := NewInstance(i.GetVersion()+1, i.GetName(), nil)
	err := i.commitSnapshot(f, dw, []string{})

	if err == nil {
		logging.DebugLogLn("Snapshot of", i.GetImageTag(), "to", newInstance.GetImageTag(), "complete.")
	}
	logging.DebugLogLn("New instance: ", newInstance.GetVersion(), newInstance.GetName(),
		newInstance.GetStartCommand())
	return newInstance, err
}

func (i Instance) commitSnapshot(f Finder, dw DockerWrapper, securityOptions []string) error {
	containerFound, container, err := f.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return err
	}

	containerID := container.ID
	if !containerFound {
		fmt.Fprintf(os.Stderr, "Container not found matching '%s; instantiating new one", i.GetImageTag())
		containerID, err = i.Instantiate(ContainerOptions{}, securityOptions)
		if err != nil {
			return err
		}
		fmt.Println("Instantiated ID ", containerID)
	}

	logging.DebugLogLn("Committing a snapshot of", containerID)

	snapshotTag := i.GetImageTagSuccessor()
	return commitContainer(dw, containerID, snapshotTag, fmt.Sprintf("commit created by trtl (%s -> %s)",
		i.GetImageTag(), snapshotTag))
}
