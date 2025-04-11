package realdocker

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/stretchr/testify/assert"
)

func TestFindContainerSuccessfully(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:        nil,
		Containers: []container.Summary{{ID: "cdef", Image: "cdef"}, {ID: "abcd", Image: "abcd"}},
	}

	found, containers, err := f.FindContainer(d, "abcd")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "abcd", containers.Image)
}

func TestFindContainerReturnsDockerError(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:        errors.New("error finding container"),
		Containers: []container.Summary{},
	}

	found, containers, err := f.FindContainer(d, "abcd")
	assert.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, container.Summary{}, containers)
}

func TestFindContainerReturnsFalseWhenNoMatchingContainer(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:        nil,
		Containers: []container.Summary{},
	}

	found, containers, err := f.FindContainer(d, "abcd")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, container.Summary{}, containers)
}

func TestFindImageSuccessfully(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:    nil,
		Images: []image.Summary{{ID: "abcd"}, {ID: "cdef"}},
	}

	imageID, err := f.FindImage(d, "abcd")
	assert.NoError(t, err)
	assert.Equal(t, imageID, "cdef")
}

func TestFindImageReturnsDockerError(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:    errors.New("error finding image"),
		Images: []image.Summary{},
	}

	imageID, err := f.FindImage(d, "abcd")
	assert.Error(t, err)
	assert.Equal(t, imageID, "")
}

func TestFindContainerReturnsFalseWhenNoMatchingImage(t *testing.T) {
	f := DockerFinder{}
	d := FakeDockerWrapper{
		Err:    nil,
		Images: []image.Summary{},
	}

	imageID, err := f.FindImage(d, "abcd")
	assert.NoError(t, err)
	assert.Equal(t, imageID, "")
}
