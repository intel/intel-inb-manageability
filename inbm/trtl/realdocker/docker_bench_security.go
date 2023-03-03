/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"github.com/docker/docker/api/types/container"
	"math/rand"
	"strconv"
	"time"
)

const imageName = "docker-bench-security"
const script = "./docker-bench-security.sh"

func DockerBenchSecurity(dw DockerWrapper) error {
	rand.Seed(time.Now().UnixNano())
	containerName := "DBS-" + strconv.Itoa(rand.Intn(10000000))
	containerId, err := createPrivilegedContainer(dw, containerName)
	if err != nil {
		return err
	}

	if err = StartContainer(dw, containerId); err != nil {
		return err
	}

	if err = Exec(dw, containerId, []string{script, "-c", "check_4_1,check_4_2,check_4_3,check_4_4,check_4_5,check_4_6,check_4_7,check_4_8,check_4_9,check_4_10,check_4_11,check_5_1,check_5_2,check_5_3,check_5_4,check_5_5,check_5_6,check_5_7,check_5_8,check_5_9,check_5_10,check_5_11,check_5_12,check_5_13,check_5_14,check_5_15,check_5_16,check_5_17,check_5_18,check_5_19,check_5_20,check_5_21,check_5_22,check_5_23,check_5_24,check_5_25,check_5_26,check_5_27,check_5_28,check_5_29,check_5_30,check_5_31"}); err != nil {
		return err
	}

	if err = StopContainer(dw, containerId); err != nil {
		return err
	}

	if err = RemoveContainer(dw, containerId, true); err != nil {
		return err
	}

	return nil
}

// CreateContainer instantiates a new container that only runs docker bench security.
// It allocates a terminal for the container so that e.g. /bin/sh can keep running in the background.
// It returns the containerID and any error encountered.
func createPrivilegedContainer(dw DockerWrapper, containerName string) (string, error) {
	hostConfig := container.HostConfig{
		NetworkMode: "host",
		PidMode:     "host",
		Binds: []string{
			"/var/lib:/var/lib",
			"/var/run/docker.sock:/var/run/docker.sock",
			"/usr/lib/systemd:/usr/lib/systemd",
			"/etc:/etc"},
	}

	options := ContainerOptions{
		Label: []string{"docker_bench_security"}}

	return CreateContainer(dw, imageName, containerName, CreateStartCommand(), options, hostConfig)
}
