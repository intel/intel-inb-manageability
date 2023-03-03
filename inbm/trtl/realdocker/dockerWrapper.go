/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"github.com/docker/docker/api/types/registry"
	"io"
	"log"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
	"os"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// DockerWrap is a struct that contains DockerInfo-specific instance information
type DockerWrap struct{}

// DockerWrapper is an interface used for all docker commands
type DockerWrapper interface {
	Events(types.EventsOptions) (<-chan events.Message, <-chan error)
	ImageImport(string, string, []string) error
	ImagePull(referenceName string, options types.ImagePullOptions) error
	ImageRemove(string, types.ImageRemoveOptions) error
	ImageList(types.ImageListOptions) ([]types.ImageSummary, error)
	ImageLoad(io.Reader, bool) error
	ContainerCommit(string, types.ContainerCommitOptions) (types.IDResponse, error)
	ContainerCreate(*container.Config, *container.HostConfig, *network.NetworkingConfig, *specs.Platform, string) (container.ContainerCreateCreatedBody, error)
	ContainerExecAttach(string, types.ExecStartCheck) error
	ContainerExecCreate(string, types.ExecConfig) (types.IDResponse, error)
	ContainerInspect(string) (types.ContainerJSON, error)
	ContainerList(types.ContainerListOptions) ([]types.Container, error)
	ContainerLogs(types.ContainerLogsOptions, string) error
	ContainerRemove(string, types.ContainerRemoveOptions) error
	ContainerStats(string, bool) (types.ContainerStats, error)
	ContainerStart(string, types.ContainerStartOptions) error
	ContainerStop(string, *time.Duration) error
	CopyToContainer(string, string, io.Reader, types.CopyToContainerOptions) error
	Login(types.AuthConfig) (registry.AuthenticateOKBody, error)
}

// Events makes actual call to docker to get the events and constantly polls.
func (dw DockerWrap) Events(options types.EventsOptions) (<-chan events.Message, <-chan error) {
	errsChan := make(chan error, 1)
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		errsChan <- err
		return nil, errsChan
	}
	return cli.Events(context.Background(), options)
}

// ImageImport makes actual call to docker to import an image.
func (dw DockerWrap) ImageImport(src string, ref string, changes []string) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	read, err := cli.ImageImport(context.Background(), types.ImageImportSource{Source: nil, SourceName: src}, ref,
		types.ImageImportOptions{Tag: "", Message: "Imported image", Changes: changes})

	defer func() {
		if read != nil {
			if err = read.Close(); err != nil {
				log.Fatalf("Error closing standard input from docker import:%s", err)
			}
		}
	}()

	return err
}

// ImagePull requests the docker host to pull an image from a remote registry.
func (dw DockerWrap) ImagePull(reference string, options types.ImagePullOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	r, err := cli.ImagePull(context.Background(), reference, options)
	if err != nil {
		return err
	}

	if _, err = io.Copy(os.Stdout, r); err != nil {
		return err
	}

	defer func() {
		if r != nil {
			if err = r.Close(); err != nil {
				log.Fatalf("Error closing standard input from image pull: %s", err)
			}
		}
	}()

	return err
}

// ImageRemove makes actual call to docker to remove an image.
func (dw DockerWrap) ImageRemove(imageID string, options types.ImageRemoveOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	_, err = cli.ImageRemove(context.Background(), imageID, types.ImageRemoveOptions{PruneChildren: options.PruneChildren, Force: options.Force})
	return err
}

// ImageList makes actual call to docker to get the image list.
func (dw DockerWrap) ImageList(options types.ImageListOptions) ([]types.ImageSummary, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return cli.ImageList(context.Background(), options)
}

// ImageLoad makes actual call to docker to load the image.
// ImageLoadResponse returned by this function.
func (dw DockerWrap) ImageLoad(input io.Reader, quiet bool) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	response, err := cli.ImageLoad(context.Background(), input, quiet)

	defer func() {
		if response.Body != nil {
			if err = response.Body.Close(); err != nil {
				log.Fatalf("Error closing standard input from docker load: %s", err)
			}
		}
	}()

	return err
}

// ContainerCommit makes the actual call to docker to commit the container.
func (dw DockerWrap) ContainerCommit(containerID string, options types.ContainerCommitOptions) (types.IDResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return types.IDResponse{}, err
	}

	return cli.ContainerCommit(context.Background(), containerID, options)
}

func (dw DockerWrap) ContainerExecCreate(container string, config types.ExecConfig) (types.IDResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return types.IDResponse{}, err
	}
	return cli.ContainerExecCreate(context.Background(), container, config)
}

// ContainerCreate makes the actual call to docker to create the container.
func (dw DockerWrap) ContainerCreate(config *container.Config, hostConfig *container.HostConfig,
	netConfig *network.NetworkingConfig, platform *specs.Platform, containerName string) (container.ContainerCreateCreatedBody, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return container.ContainerCreateCreatedBody{}, err
	}

	return cli.ContainerCreate(context.Background(), config, hostConfig, netConfig, platform, containerName)
}

func (dw DockerWrap) ContainerExecAttach(execID string, startCheck types.ExecStartCheck) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	execAttachResponse, err := cli.ContainerExecAttach(context.Background(), execID, startCheck)
	defer execAttachResponse.Close()

	if _, err = io.Copy(os.Stdout, execAttachResponse.Reader); err != nil {
		return err
	}

	return nil
}

// ContainerList makes the actual call to docker to list the containers.
func (dw DockerWrap) ContainerList(options types.ContainerListOptions) ([]types.Container, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return cli.ContainerList(context.Background(), options)
}

// ContainerLogs makes the actual call to docker to get logs for the container.
func (dw DockerWrap) ContainerLogs(options types.ContainerLogsOptions, container string) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	r, err := cli.ContainerLogs(context.Background(), container, options)
	if err != nil {
		return err
	}

	if _, err = io.Copy(os.Stdout, r); err != nil {
		return err
	}

	defer func() {
		if r != nil {
			if err = r.Close(); err != nil {
				log.Fatalf("Error closing standard input from docker logs: %s", err)
			}
		}
	}()

	return nil
}

// ContainerRemove makes the actual call to docker to remove a container.
func (dw DockerWrap) ContainerRemove(containerID string, options types.ContainerRemoveOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerRemove(context.Background(), containerID, options)
}

// ContainerStart makes the actual call to docker to inspect a container.
func (dw DockerWrap) ContainerStart(containerID string, options types.ContainerStartOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerStart(context.Background(), containerID, options)
}

// ContainerStats makes tha actual call to docker to get container statistics.
func (dw DockerWrap) ContainerStats(containerID string, stream bool) (types.ContainerStats, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return types.ContainerStats{}, err
	}

	response, err := cli.ContainerStats(context.Background(), containerID, stream)

	return response, err
}

// ContainerStop makes the actual call to docker to stop a container.
func (dw DockerWrap) ContainerStop(containerID string, timeout *time.Duration) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerStop(context.Background(), containerID, timeout)
}

// ContainerInspect makes the actual call to docker to inspect a container.
func (dw DockerWrap) ContainerInspect(containerID string) (types.ContainerJSON, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return types.ContainerJSON{}, err
	}

	return cli.ContainerInspect(context.Background(), containerID)
}

// CopyToContainer makes the actual call to docker to copy to the container.
func (dw DockerWrap) CopyToContainer(containerID string, path string, content io.Reader, options types.CopyToContainerOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.CopyToContainer(context.Background(), containerID, path, content, options)
}

// Login authenticates a server with the given authentication credentials
func (dw DockerWrap) Login(config types.AuthConfig) (registry.AuthenticateOKBody, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return registry.AuthenticateOKBody{}, err
	}

	return cli.RegistryLogin(context.Background(), config)
}
