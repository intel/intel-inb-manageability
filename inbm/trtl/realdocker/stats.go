/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"encoding/json"
	"fmt"
	"log"
   	"math"

	"github.com/docker/docker/api/types"
)

func getSingleContainerStats(dw DockerWrapper, container ContainerInfo) (ContainerUsage, error) {
	var containerUsage ContainerUsage

	response, err := dw.ContainerStats(container.ID, false)
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

    memoryUsage := v.MemoryStats.Usage
    memoryLimit := v.MemoryStats.Limit
    memoryPercent := (float64(memoryUsage) / float64(memoryLimit)) * 100.0

	return  ContainerUsage{
			ImageName:  container.ImageName,
			ContainerID: container.ID,
			CPUPercent: math.Round(cpuPercent*100)/100,
			MemoryUsage: memoryUsage,
			MemoryLimit: memoryLimit,
			MemoryPercent: math.Round(memoryPercent*100)/100,
			Pids: v.PidsStats.Current}, nil
}

func createContainerUsages(dw DockerWrapper, containers []ContainerInfo) (string, error) {
	usages := make([]ContainerUsage, 0)
	for _, container := range containers {
		s, err := getSingleContainerStats(dw, container)
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
func Stats(dw DockerWrapper) error {
    containers, err := GetAllRunningContainers(dw)
	if err != nil {
		return err
	}

	output, err := createContainerUsages(dw, containers)
	if err != nil {
		return err
	}

  fmt.Println("ContainerStats=", output)
  return nil
}

// AllContainerUsage is a structure to marshal the container usage information in JSON format
type allContainerUsage struct {
	// Containers is a slice of ContainerUsages
	Containers []ContainerUsage `json:"containers"`
}

// ContainerUsage is a structure to hold container usage.
type ContainerUsage struct {
    ImageName string `json:"imageName"`
    // Name is the name of the container
    ContainerID string `json:"containerID"`
    // CpuPercent is the CPU percentage used by the container.
    CPUPercent float64 `json:"cpuPercent"`
    // MemoryUsage is the amount of memory used by the container
    MemoryUsage uint64 `json:"memoryUsage"`
    // MemoryLimit is the total memory on the system
    MemoryLimit uint64 `json:"memoryLimit"`
    // MemoryPercent is the Memory percentage used by the container
    MemoryPercent float64 `json:"memoryPercent`
    // Pids is the number of Pids used by the container
    Pids uint64 `json:"pids"`
}

func createAllContainerUsageJSON(containers []ContainerUsage) (string, error) {
	c := &allContainerUsage{
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
