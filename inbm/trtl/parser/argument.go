/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

// Package parser is used to parse and verify user provided arguments.
package parser

import (
	"errors"
	"strings"

	"iotg-inb/trtl/factory"
)

const (
	// Commit is a string declaration for Commit command.
	Commit = "commit"

	// ContainerCopy is a string declaration for ContainerCopy command.
	ContainerCopy = "containercopy"

	// ContainerRemove is a string declaration for ContainerRemove command.
	ContainerRemove = "containerremove"

	// ContainerRemoveByID is a string declaration for ContainerRemoveByID command.
	ContainerRemoveByID = "containerremovebyid"

	// ContainerRemoveAll is a string declaration for ContainerRemoveAll command.
	ContainerRemoveAll = "containerremoveall"

	// DeleteSnapshot is a string declaration for DeleteSnapshot command.
	DeleteSnapshot = "deletesnapshot"

	// DockerBenchSecurity is a string declaration for DockerBenchSecurity command.
	DockerBenchSecurity = "dockerbenchsecurity"

	// Down is a string declaration for Docker Compose
	Down = "down"

	// Events is a string declaration for Events command
	Events = "events"

	// Exec is a string declaration for Exec command.
	Exec = "exec"

	// GetImageByContainerId is a string declaration for GetImageByContainerid.
	GetImageByContainerId = "getimagebycontainerid"

	// GetLatestTag is a string declaration for GetLatestTag command.
	GetLatestTag = "getlatesttag"

	// ImageDeleteOld is a string declaration for ImageDeleteOld command.
	ImageDeleteOld = "imagedeleteold"

	// ImagePull is a string declaration for ImagePull command.
	ImagePull = "imagepull"

	// ImageRemove is a string declaration for ImageRemove command.
	ImageRemove = "imageremove"

	// ImageRemoveAll is a string declaration for ImageRemoveAll command.
	ImageRemoveAll = "imageremoveall"

	// ImageRemoveById is a string declaration for ImageRemoveById command.
	ImageRemoveById = "imageremovebyid"

	// Import is a string declaration for Import command.
	Import = "import"

	// List is a string declaration for List command.
	List = "list"

	// Load is a string declaration for Load command.
	Load = "load"

	// Authenticates a server with the given authentication credentials.
	Login = "login"

	// Logs is a string declaration for Logs command.
	Logs = "logs"

	// Pull is a string declaration for Docker Compose pull.
	Pull = "pull"

	// SingleSnapshot is a string declaration for SingleSnapshot command.
	SingleSnapshot = "singlesnapshot"

	// Rollback is a string declaration for Rollback command.
	Rollback = "rollback"

	// Snapshot is a string declaration for Snapshot command.
	Snapshot = "snapshot"

	// Start is a string declaration for Start command.
	Start = "start"

	// Stats is a string declaration for Stats command.
	Stats = "stats"

	// Stop is a string declaration for Stop command.
	Stop = "stop"

	// StopByID is a string declaration for Stop command by container ID.
	StopByID = "stopbyid"

	// StopAll is a string declaration for StopAll command.
	StopAll = "stopall"

	// UndoChange is a string declaration for UndoChange command.
	UndoChange = "undochange"

	// UP is a string declaration for Up command.
	Up = "up"

	noCommand = "none"
)

// InArray checks to see if the given string value exists in the given string array.
// It returns true if the value is in the array; otherwise, false.
func InArray(val string, array []string) (exists bool) {
	for _, v := range array {
		if val == v {
			return true
		}
	}
	return false
}

// ValidateBoxType verifies that a box type was provided and that it matches
// one of the supported types.
// It returns the box name if valid or any error encountered.
func ValidateBoxType(c string) (string, error) {
	if c == "" {
		return factory.None, errors.New("box type parameter was empty")
	}

	containerTypes := []string{factory.Btrfs, factory.Docker, factory.Compose}
	lc := strings.ToLower(c)
	if InArray(lc, containerTypes) {
		return lc, nil
	}

	return factory.None, errors.New("unrecognized box type")
}

// ValidateCommandType verifies that a command type was provided and that it matches
// one of the supported commands.
// It returns the command name if valid or any error encountered.
func ValidateCommandType(c string, b string) (string, error) {
	if c == "" {
		return noCommand, errors.New("command parameter was empty")
	}

	containerCommandTypes := []string{Commit, ContainerCopy, ContainerRemove, ContainerRemoveByID, ContainerRemoveAll,
		DockerBenchSecurity, Exec, Events, GetImageByContainerId, GetLatestTag, ImageDeleteOld, ImagePull,
		ImageRemove, ImageRemoveAll, ImageRemoveById, Import, List, Load, Login, Logs, Rollback, Snapshot, Start, Stats,
		Stop, StopAll, StopByID}

	nativeCommandTypes := []string{DeleteSnapshot, List, SingleSnapshot, UndoChange}

	composeCommandTypes := []string{Down, Up, List, Logs, Login, Pull, ImageRemoveAll}

	if b == factory.Docker {
		if InArray(c, containerCommandTypes) {
			return c, nil
		}
	}

	if b == factory.Compose {
		if InArray(c, composeCommandTypes) {
			return c, nil
		}
	}

	if b == factory.Btrfs {
		if InArray(c, nativeCommandTypes) {
			return c, nil
		}
	}

	return noCommand, errors.New("unrecognized command type for " + b)
}
