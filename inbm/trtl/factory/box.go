/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

// Package factory is a high level package for all common code and factories
// for handling multiple management APIs.
package factory

import "errors"

// Boxer is a high level interface of methods used by all concrete types.
type Boxer interface {
	List(instanceName string)
}

// Snapper is an interface to be used by snapper.
type Snapper interface {
	Boxer
	DeleteSnapshot(configName string, snapshotNumber int)
	SingleSnapshot(configName string, desc string)
	UndoChange(configName string, snapshotVersion int)
}

type Composer interface {
	Boxer
	Down(instanceName string)
	DownWithFile(instanceName string, fileName string)
	Up(instanceName string)
	UpWithFile(instanceName string, fileName string)
	Pull(instanceName string)
	PullWithFile(instanceName string, fileName string)
	Login(username string, serverName string)
	Logs(instanceName string, options string, target string)
	ImageRemoveAll(instanceName string, force bool)
}

// Container is an interface to be used by all containers.
type Container interface {
	Boxer
	Snapshot(instanceName string, instanceVersion int, autoMode bool)
	ContainerCopy(source string, fileName string, path string)
	ContainerRemove(instanceName string, instanceVersion int, force bool)
	ContainerRemoveByID(containerID string, force bool)
	ContainerRemoveAll(instanceName string, force bool)
	ContainerStopByID(containerID string)
	GetImageByContainerId(containerID string)
	GetLatestTag(instanceName string)
	DockerBenchSecurity()
	Exec(instanceName string, instanceVersion int, execCommand []string, options string,
		securityOptions []string)
	Events()
	ImageDeleteOld(numImagesKept int, instanceName string)
	ImageImport(refString string, source string, maxWaitSeconds int, overwriteImageFlag bool)
	ImagePull(refString string, userName string, maxWaitSeconds int)
	ImageRemove(instanceName string, instanceVersion int, force bool)
	ImageRemoveAll(instanceName string, force bool)
	ImageRemoveByID(imageID string, force bool)
	Load(input string, ref string, maxWaitSeconds int)
	Login(username string, serverName string)
	Logs(instanceName string, options string, target string)
	Rollback(instanceName string, instanceVersion int, snapshotName string, snapshotVersion int)
	Start(instanceName string, instanceVersion int, options string, securityOptions []string)
	Stats()
	Stop(instanceName string, instanceVersion int)
	StopAll(instanceName string)
	Commit(instanceName string, instanceVersion int)
}

const (
	// Docker is a string representing Docker container management.
	Docker = "docker"

	// Btrfs is a string representing the BTR file system.
	Btrfs = "btrfs"

	// Compose is a string representing Docker Compose
	Compose = "compose"

	// None is a string used when a type is entered that is not supported.
	// Used by argument verification in the instance that an incorrect value was given.
	None = "none"
)

// CreateBox creates the current concrete class based on the management system used.
func CreateBox(t string) (Boxer, error) {
	switch t {
	case Docker:
		return new(DockerInfo), nil
	case Btrfs:
		return new(SnapperInfo), nil
	case Compose:
		return new(ComposeInfo), nil
	default:
		return nil, errors.New("invalid Box Type")
	}
}
