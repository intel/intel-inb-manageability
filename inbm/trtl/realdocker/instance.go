/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

// Instance represents an instance backed by Docker
type Instance struct {
	version      int
	name         string
	startCommand []string
}

// GetVersion returns the Docker version associated with the instance
func (i Instance) GetVersion() int {
	return i.version
}

// GetName returns the Docker repository tag associated with the Docker image
// backing the Instance
func (i Instance) GetName() string {
	return i.name
}

// GetStartCommand returns the default start command used when instantiating
// a container based on the instance/Docker image
func (i Instance) GetStartCommand() []string {
	return i.startCommand
}

// NewInstance is a factory method for this struct
func NewInstance(version int, name string, startCommand []string) Instance {
	return Instance{version: version, name: name, startCommand: startCommand}
}
