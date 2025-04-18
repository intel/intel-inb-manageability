/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/docker/docker/api/types/common"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"

	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/net/context"
)

// DockerWrap is a struct that contains DockerInfo-specific instance information
type DockerWrap struct{}

// DockerWrapper is an interface used for all docker commands
type DockerWrapper interface {
	Events(events.ListOptions) (<-chan events.Message, <-chan error)
	ImageImport(string, string, []string) error
	ImagePull(string, image.PullOptions) error
	ImageRemove(string, image.RemoveOptions) error
	ImageList(image.ListOptions) ([]image.Summary, error)
	ImageLoad(io.Reader, bool) error
	ContainerCommit(string, container.CommitOptions) (container.CommitResponse, error)
	ContainerCreate(*container.Config, *container.HostConfig, *network.NetworkingConfig, *specs.Platform, string) (container.CreateResponse, error)
	ContainerExecAttach(string, container.ExecStartOptions) error
	ContainerExecCreate(string, container.ExecOptions) (container.ExecCreateResponse, error)
	ContainerInspect(string) (container.InspectResponse, error)
	ContainerList(container.ListOptions) ([]container.Summary, error)
	ContainerLogs(container.LogsOptions, string) error
	ContainerRemove(string, container.RemoveOptions) error
	ContainerStats(string, bool) (container.StatsResponse, error)
	ContainerStart(string, container.StartOptions) error
	ContainerStop(string, *int) error
	CopyToContainer(string, string, io.Reader, container.CopyToContainerOptions) error
	Login(registry.AuthConfig) (registry.AuthenticateOKBody, error)
}

// Events makes actual call to docker to get the events and constantly polls.
func (dw DockerWrap) Events(options events.ListOptions) (<-chan events.Message, <-chan error) {
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

	read, err := cli.ImageImport(context.Background(), image.ImportSource{Source: nil, SourceName: src}, ref,
		image.ImportOptions{Tag: "", Message: "Imported image", Changes: changes})

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
func (dw DockerWrap) ImagePull(reference string, options image.PullOptions) error {
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
func (dw DockerWrap) ImageRemove(imageID string, options image.RemoveOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	_, err = cli.ImageRemove(context.Background(), imageID, image.RemoveOptions{PruneChildren: options.PruneChildren, Force: options.Force})
	return err
}

// ImageList makes actual call to docker to get the image list.
func (dw DockerWrap) ImageList(options image.ListOptions) ([]image.Summary, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return cli.ImageList(context.Background(), options)
}

// ImageLoad makes actual call to docker to load the image.
// ImageLoadResponse returned by this function.
func (dw DockerWrap) ImageLoad(input io.Reader, isQuiet bool) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	response, err := cli.ImageLoad(context.Background(), input, client.ImageLoadWithQuiet(isQuiet))
	if err != nil {
		return fmt.Errorf("error loading image: %w", err)
	}

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
func (dw DockerWrap) ContainerCommit(containerID string, options container.CommitOptions) (container.CommitResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return container.CommitResponse{}, fmt.Errorf("error creating docker client: %w", err)
	}

	return cli.ContainerCommit(context.Background(), containerID, options)
}

// ContainerExecCreate makes the actual call to docker to create an exec instance.
func (dw DockerWrap) ContainerExecCreate(container string, config container.ExecOptions) (common.IDResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return common.IDResponse{}, err
	}
	return cli.ContainerExecCreate(context.Background(), container, config)
}

// ContainerCreate makes the actual call to docker to create the container.
func (dw DockerWrap) ContainerCreate(config *container.Config, hostConfig *container.HostConfig,
	netConfig *network.NetworkingConfig, platform *specs.Platform, containerName string) (container.CreateResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return container.CreateResponse{}, err
	}

	return cli.ContainerCreate(context.Background(), config, hostConfig, netConfig, platform, containerName)
}

// ContainerExecAttach makes the actual call to docker to attach to an exec instance.
func (dw DockerWrap) ContainerExecAttach(execID string, startCheck container.ExecStartOptions) error {
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
func (dw DockerWrap) ContainerList(options container.ListOptions) ([]container.Summary, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return cli.ContainerList(context.Background(), options)
}

// ContainerLogs makes the actual call to docker to get logs for the container.
func (dw DockerWrap) ContainerLogs(options container.LogsOptions, container string) error {
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
func (dw DockerWrap) ContainerRemove(containerID string, options container.RemoveOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerRemove(context.Background(), containerID, options)
}

// ContainerStart makes the actual call to docker to inspect a container.
func (dw DockerWrap) ContainerStart(containerID string, options container.StartOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerStart(context.Background(), containerID, options)
}

// ContainerStats makes tha actual call to docker to get container statistics.
func (dw DockerWrap) ContainerStats(containerID string, isStream bool) (container.StatsResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return container.StatsResponse{}, err
	}

	stats, err := cli.ContainerStats(context.Background(), containerID, isStream)
	if err != nil {
		return container.StatsResponse{}, fmt.Errorf("error retrieving container stats: %w", err)
	}
	defer stats.Body.Close()

	var containerStats container.StatsResponse
	if err := json.NewDecoder(stats.Body).Decode(&containerStats); err != nil {
		return container.StatsResponse{}, fmt.Errorf("error decoding container stats: %w", err)
	}
	return containerStats, err
}

// ContainerStop makes the actual call to docker to stop a container.
// timeout is # of seconds
func (dw DockerWrap) ContainerStop(containerID string, timeout *int) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.ContainerStop(context.Background(), containerID, container.StopOptions{Timeout: timeout})
}

// ContainerInspect makes the actual call to docker to inspect a container.
func (dw DockerWrap) ContainerInspect(containerID string) (container.InspectResponse, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return container.InspectResponse{}, err
	}

	return cli.ContainerInspect(context.Background(), containerID)
}

// CopyToContainer makes the actual call to docker to copy to the container.
func (dw DockerWrap) CopyToContainer(containerID string, path string, content io.Reader, options container.CopyToContainerOptions) error {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	return cli.CopyToContainer(context.Background(), containerID, path, content, options)
}

// Login authenticates a server with the given authentication credentials
func (dw DockerWrap) Login(config registry.AuthConfig) (registry.AuthenticateOKBody, error) {
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return registry.AuthenticateOKBody{}, err
	}

	return cli.RegistryLogin(context.Background(), config)
}
