/*
    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/docker/docker/api/types"
)

func getSingleContainerStats(dw DockerWrapper, imageName string, containerID string) (ContainerUsage, error) {
	var containerUsage ContainerUsage

	response, err := dw.ContainerStats(containerID, false)
	if err != nil {
		return containerUsage, err
	}

	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Fatalf("Error closing response body from docker stats command: %s", err)
		}
	}()

	dec := json.NewDecoder(response.Body)

	var (
		previousCPU    uint64
		previousSystem uint64
		v              *types.StatsJSON
	)

	if err = dec.Decode(&v); err != nil {
		return containerUsage, err
	}

	previousCPU = v.PreCPUStats.CPUUsage.TotalUsage
	previousSystem = v.PreCPUStats.SystemUsage
	cpuPercent := calculateCPUPercent(previousCPU, previousSystem, v)

	containerUsage = createContainerUsage(imageName, cpuPercent)
	return containerUsage, err
}

func statsAll(dw DockerWrapper) (string, error) {
	containers, err := GetAllContainers(dw, true, "")
	if err != nil {
		return "", err
	}

	return createContainerUsages(dw, containers)
}

func createContainerUsages(dw DockerWrapper, containers []types.Container) (string, error) {
	usages := make([]ContainerUsage, 0)
	for _, container := range containers {
		s, err := getSingleContainerStats(dw, container.Image, container.ID)
		if err != nil {
			return "", err
		}
		usages = append(usages, s)
	}

	j, err := createAllContainerUsageJSON(usages)
	if err != nil {
		return "", err
	}

	return j, nil
}

// Stats retrieves container usage data using the docker Stats API.  It can get stats for all containers or just
// one specified container.
// It returns any error encountered.
func (i Instance) Stats(f Finder, dw DockerWrapper, all bool) error {
	if all {
		output, err := statsAll(dw)
		if err != nil {
			return err
		}
		fmt.Println("ContainerStats=", output)
		return nil
	}

	containerFound, container, err := f.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return err
	}
	if !containerFound {
		return errors.New("Unable to fetch container stats. Container not found matching " + i.GetImageTag())
	}

	cu, err := getSingleContainerStats(dw, i.GetImageTag(), container.ID)
	if err != nil {
		return err
	}

	usages := make([]ContainerUsage, 0)
	usages = append(usages, cu)
	output, err := createAllContainerUsageJSON(usages)
	if err != nil {
		return err
	}
	fmt.Println("ContainerStats=", output)
	return nil

}

// AllContainerUsage is a structure to marshal the container usage information in JSON format
type AllContainerUsage struct {
	// Containers is a slice of ContainerUsages
	Containers []ContainerUsage `json:"containers"`
}

// ContainerUsage is a structure to hold container usage.
type ContainerUsage struct {
	// Name is the name of the container
	Name string `json:"name"`
	// CpuPercent is the CPU percentage used by the container.
	CPUPercent float64 `json:"cpuPercent"`
}

func createContainerUsage(name string, cpuPercent float64) ContainerUsage {
	c := &ContainerUsage{
		Name:       name,
		CPUPercent: cpuPercent}
	return *c
}

func createAllContainerUsageJSON(containers []ContainerUsage) (string, error) {
	c := &AllContainerUsage{
		Containers: containers}
	j, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(j), nil
}

func calculateCPUPercent(previousCPU, previousSystem uint64, v *types.StatsJSON) float64 {
	var (
		cpuPercent  = 0.0
		cpuDelta    = float64(v.CPUStats.CPUUsage.TotalUsage) - float64(previousCPU)
		systemDelta = float64(v.CPUStats.SystemUsage) - float64(previousSystem)
	)

	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(len(v.CPUStats.CPUUsage.PercpuUsage)) * 100.0
	}
	return cpuPercent
}
