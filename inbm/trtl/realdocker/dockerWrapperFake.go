/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"io"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
)

// FakeFinder is a structure used to set outgoing parameters of fake methods for the Finder interface.
type FakeFinder struct {
	Container container.Summary
	Err       error
	IsFound   bool
	ImageID   string
}

// FindImage is a fake method for unit testing.
func (f FakeFinder) FindImage(DockerWrapper, string) (string, error) {
	return f.ImageID, f.Err
}

// FindContainer is a fake method for unit testing.
func (f FakeFinder) FindContainer(DockerWrapper, string) (bool, container.Summary, error) {
	return f.IsFound, f.Container, f.Err
}

// FakeDockerWrapper is a structure used to set outgoing parameters of fake methods for the DockerWrapper interface.
type FakeDockerWrapper struct {
	AuthenticateOKBody registry.AuthenticateOKBody
	Err                error
	Images             []image.Summary
	ContainerJSON      container.InspectResponse
	Containers         []container.Summary
	HijackedResp       types.HijackedResponse
	Stats              container.StatsResponse
	CommitResponse     container.CommitResponse
	ExecCreateResponse container.ExecCreateResponse
	CreatedBody        container.CreateResponse
	ErrorChan          <-chan error
	MessageChan        <-chan events.Message
}

// Events is a fake method for unit testing.
func (d FakeDockerWrapper) Events(events.ListOptions) (<-chan events.Message, <-chan error) {
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
func (d FakeDockerWrapper) ImagePull(string, image.PullOptions) error {
	return d.Err
}

// ImageRemove is a fake method for unit testing
func (d FakeDockerWrapper) ImageRemove(string, image.RemoveOptions) error {
	return d.Err
}

// ImageList is a fake method for unit testing
func (d FakeDockerWrapper) ImageList(image.ListOptions) ([]image.Summary, error) {
	return d.Images, d.Err
}

// ContainerCommit is a fake method for unit testing
func (d FakeDockerWrapper) ContainerCommit(string, container.CommitOptions) (container.CommitResponse, error) {
	return d.CommitResponse, d.Err
}

// ContainerCreate makes the actual call to docker to create the container.
func (d FakeDockerWrapper) ContainerCreate(*container.Config, *container.HostConfig,
	*network.NetworkingConfig, *specs.Platform, string) (container.CreateResponse, error) {

	return d.CreatedBody, d.Err
}

// ContainerList is a fake method for unit testing
func (d FakeDockerWrapper) ContainerList(container.ListOptions) ([]container.Summary, error) {
	return d.Containers, d.Err
}

// ContainerLogs is a fake method for unit testing
func (d FakeDockerWrapper) ContainerLogs(container.LogsOptions, string) error {
	return d.Err
}

// ContainerRemove is a fake method for unit testing
func (d FakeDockerWrapper) ContainerRemove(string, container.RemoveOptions) error {
	return d.Err
}

// ContainerStart is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStart(string, container.StartOptions) error {
	return d.Err
}

// ContainerStats is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStats(string, bool) (container.StatsResponse, error) {
	return d.Stats, d.Err
}

// ContainerStop is a fake method for unit testing
func (d FakeDockerWrapper) ContainerStop(string, *int) error {
	return d.Err
}

// ContainerInspect is a fake method for unit testing
func (d FakeDockerWrapper) ContainerInspect(string) (container.InspectResponse, error) {
	return d.ContainerJSON, d.Err
}

// CopyToContainer is a fake method for unit testing
func (d FakeDockerWrapper) CopyToContainer(string, string, io.Reader, container.CopyToContainerOptions) error {
	return d.Err
}

// ContainerExecAttach is a fake method for unit testing
func (d FakeDockerWrapper) ContainerExecAttach(string, container.ExecStartOptions) error {
	return d.Err
}

// ContainerExecCreate is a fake method for unit testing
func (d FakeDockerWrapper) ContainerExecCreate(string, container.ExecOptions) (container.ExecCreateResponse, error) {
	return d.ExecCreateResponse, d.Err
}

// Login is a fake method for unit testing
func (d FakeDockerWrapper) Login(registry.AuthConfig) (registry.AuthenticateOKBody, error) {
	return d.AuthenticateOKBody, d.Err
}
