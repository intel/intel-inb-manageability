/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"github.com/docker/docker/api/types/registry"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
)

// FakeFinder is a structure used to set outgoing parameters of fake methods for the Finder interface.
type FakeFinder struct {
	Container types.Container
	Err       error
	IsFound   bool
	ImageID   string
}

// FindImage is a fake method for unit testing.
func (f FakeFinder) FindImage(DockerWrapper, string) (string, error) {
	return f.ImageID, f.Err
}

// FindContainer is a fake method for unit testing.
func (f FakeFinder) FindContainer(DockerWrapper, string) (bool, types.Container, error) {
	return f.IsFound, f.Container, f.Err
}

// FakeDockerWrapper is a structure used to set outgoing parameters of fake methods for the DockerWrapper interface.
type FakeDockerWrapper struct {
	AuthenticateOKBody registry.AuthenticateOKBody
	Err                error
	Images             []types.ImageSummary
	ContainerJSON      types.ContainerJSON
	Containers         []types.Container
	HijackedResp       types.HijackedResponse
	Stats              types.ContainerStats
	IDResponse         types.IDResponse
	CreatedBody        container.ContainerCreateCreatedBody
	ErrorChan          <-chan error
	MessageChan        <-chan events.Message
}

// Events is a fake method for unit testing.
func (d FakeDockerWrapper) Events(types.EventsOptions) (<-chan events.Message, <-chan error) {
	return d.MessageChan, d.ErrorChan
}

// ImageImport is a fake method for unit testing.
func (d FakeDockerWrapper) ImageImport(string, string, []string) error {
	return d.Err
}

// ImageLoad is a fake method for unit testing.
func (d FakeDockerWrapper) ImageLoad(io.Reader, bool) error {
	return d.Err
}

// ImagePull is a fake method for unit testing.
func (d FakeDockerWrapper) ImagePull(string, types.ImagePullOptions) error {
	return d.Err
}

// ImageRemove is a fake method for unit testing
func (d FakeDockerWrapper) ImageRemove(string, types.ImageRemoveOptions) error {
	return d.Err
}

// ImageList is a fake method for unit testing
func (d FakeDockerWrapper) ImageList(types.ImageListOptions) ([]types.ImageSummary, error) {
	return d.Images, d.Err
}

// ContainerCommit is a fake method for unit testing
func (d FakeDockerWrapper) ContainerCommit(containerID string, options types.ContainerCommitOptions) (types.IDResponse, error) {
	return d.IDResponse, d.Err
}

// ContainerCreate makes the actual call to docker to create the container.
func (d FakeDockerWrapper) ContainerCreate(config *container.Config, hostConfig *container.HostConfig,
	netConfig *network.NetworkingConfig, containerName string) (container.ContainerCreateCreatedBody, error) {

	return d.CreatedBody, d.Err
}

// ContainerList is a fake method for unit testing
func (d FakeDockerWrapper) ContainerList(types.ContainerListOptions) ([]types.Container, error) {
	return d.Containers, d.Err
}

// ContainerLogs is a fake method for unit testing
func (d FakeDockerWrapper) ContainerLogs(types.ContainerLogsOptions, string) error {
	return d.Err
}

// ContainerRemove is a fake method for unit testing
func (d FakeDockerWrapper) ContainerRemove(string, types.ContainerRemoveOptions) error {
	return d.Err
}

// ContainerStart is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStart(containerID string, options types.ContainerStartOptions) error {
	return d.Err
}

// ContainerStats is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStats(containerID string, stream bool) (types.ContainerStats, error) {
	return d.Stats, d.Err
}

// ContainerStop is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStop(string, *time.Duration) error {
	return d.Err
}

// ContainerInspect is a fake method for unit testing
func (d FakeDockerWrapper) ContainerInspect(string) (types.ContainerJSON, error) {
	return d.ContainerJSON, d.Err
}

// CopyToContainer is a fake method for unit testing
func (d FakeDockerWrapper) CopyToContainer(string, string, io.Reader, types.CopyToContainerOptions) error {
	return d.Err
}

func (d FakeDockerWrapper) ContainerExecAttach(execID string, startCheck types.ExecStartCheck) error {
	return d.Err
}

func (d FakeDockerWrapper) ContainerExecCreate(container string, config types.ExecConfig) (types.IDResponse, error) {
	return d.IDResponse, d.Err
}

// Login is a fake method for unit testing
func (d FakeDockerWrapper) Login(config types.AuthConfig) (registry.AuthenticateOKBody, error) {
	return d.AuthenticateOKBody, d.Err
}
