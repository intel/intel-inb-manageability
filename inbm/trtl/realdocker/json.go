/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"encoding/json"
)

// ContainerOptions is a structure used to hold the contents of the JSON string used in creating the container.
type ContainerOptions struct {
	Device  []string
	Execcmd string
	Port    []string
	Bind    []string
	Label   []string
}

// ContainerLogOptions is a structure used to hold the contents of the JSON string used to get container logs.
type ContainerLogOptions struct {
	Details string
	Since   string
	Tail    string
}

// ContainerOptionsUnmarshal will unmarshal the contents of the JSON string into the ContainerOptions structure.
// It will return the filled in ContainerOptions structure with data from the incoming byte array.
func ContainerOptionsUnmarshal(blob []byte) ([]ContainerOptions, error) {
	var options []ContainerOptions
	err := json.Unmarshal(blob, &options)
	return options, err
}

func ContainerLogOptionsUnmarshal(blob []byte) ([]ContainerLogOptions, error) {
	var options []ContainerLogOptions
	err := json.Unmarshal(blob, &options)
	return options, err
}
