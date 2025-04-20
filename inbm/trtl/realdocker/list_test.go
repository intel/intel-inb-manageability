/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides interface abstractions 
// to interact with Docker, facilitating operations like 
// image and container manipulation.
package realdocker

import (
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/stretchr/testify/assert"
)

func TestListContainersSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []image.Summary{
			{ID: "abcd", RepoTags: []string{"abcd"}},
		},
	}

	err := ListContainers(d, "redis")
	assert.NoError(t, err)
}
func TestListContainersNoneImageSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []image.Summary{
			{ID: "abcd", RepoTags: []string{"<none>"}},
		},
	}

	err := ListContainers(d, "redis")
	assert.NoError(t, err)
}
