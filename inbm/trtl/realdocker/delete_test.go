package realdocker

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"errors"

	"github.com/docker/docker/api/types"
)

func TestImageDeleteOldSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd1", RepoTags: []string{"abcd:1"}},
			{ID: "abcd2", RepoTags: []string{"abcd:2"}},
		},
		ContainerJSON: types.ContainerJSON{},
	}

	warnIfRunningContainer = func(dw DockerWrapper, containerID string) error {
		return nil
	}

	err := ImageDeleteOld(f, d, 1, "abcd")
	assert.NoError(t, err)
}

func TestImageDeleteOldNonSequentialSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd1", RepoTags: []string{"abcd:5"}},
			{ID: "abcd2", RepoTags: []string{"abcd:8"}},
		},
		ContainerJSON: types.ContainerJSON{},
	}

	warnIfRunningContainer = func(dw DockerWrapper, containerID string) error {
		return nil
	}

	err := ImageDeleteOld(f, d, 1, "abcd")
	assert.NoError(t, err)
}

func TestImageDeleteOldErrorsWhenImageListIsEmpty(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err:    nil,
		Images: []types.ImageSummary{},
	}

	warnIfRunningContainer = func(dw DockerWrapper, containerID string) error {
		return nil
	}

	err := ImageDeleteOld(f, d, 1, "abcd")
	assert.Error(t, err)
}

func TestImageDeleteOldReturnsAnyDockerErrors(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err:    errors.New("docker error"),
		Images: []types.ImageSummary{},
	}

	warnIfRunningContainer = func(dw DockerWrapper, containerID string) error {
		return nil
	}

	err := ImageDeleteOld(f, d, 1, "abcd")
	assert.Error(t, err)
}
