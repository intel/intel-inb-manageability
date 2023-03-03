/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// CreateContainer instantiates a new container from an image, a given name, start command, and options.
// It allocates a terminal for the container so that e.g. /bin/bash can keep running in the background.
// It uses host networking for convenience.
// It returns the containerID and any error encountered.
func CreateContainer(dw DockerWrapper, image string, containerName string, cmd []string, options ContainerOptions,
	hostConfig container.HostConfig) (string, error) {
	var devices []container.DeviceMapping
	for _, d := range options.Device {
		device := container.DeviceMapping{PathOnHost: d, PathInContainer: d, CgroupPermissions: "rwm"}
		devices = append(devices, device)
	}

	hostConfig.Resources = container.Resources{Devices: devices}

	containerConfig := container.Config{
		Image: image,
		Cmd:   cmd,
		Tty:   true,
	}

	if options.Port != nil {
		for _, port := range options.Port {
			p := strings.Split(port, ":")
			var containerPort = nat.Port(p[0])
			var hostPort = p[1]

			hostConfig.PortBindings = nat.PortMap{
				containerPort: []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: hostPort,
					},
				},
			}

			containerConfig.ExposedPorts = nat.PortSet{
				containerPort: struct{}{},
			}
		}
	}

	if options.Label != nil {
		containerConfig.Labels = createLabelMap(options.Label)
	}

	if options.Bind != nil {
		hostConfig.Binds = options.Bind
	}

	networkingConfig := network.NetworkingConfig{}

	platform := specs.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}

	result, err := dw.ContainerCreate(&containerConfig, &hostConfig, &networkingConfig, &platform, containerName)
	if err != nil {
		return "", err
	}
	return result.ID, err
}

func createLabelMap(labels []string) map[string]string {
	m := make(map[string]string)
	for _, label := range labels {
		if strings.Contains(label, ":") {
			l := strings.Split(label, ":")
			m[l[0]] = l[1]
		} else {
			m[label] = ""
		}
	}
	return m
}
