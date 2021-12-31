package realdocker

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
)

func TestStopSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := Stop(f, d, "abcd")
	assert.NoError(t, err)
}

func TestStopReturnsErrorWhileFindingContainer(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{},
		Err:       errors.New("error finding container"),
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := Stop(f, d, "abcd")
	assert.Error(t, err)
}

func TestStopErrorsWhenContainerNotFound(t *testing.T) {
	f := FakeFinder{
		IsFound:   false,
		Container: types.Container{},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := Stop(f, d, "abcd")
	assert.Error(t, err)
}

func TestStopReturnsAnyDockerErrors(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err: errors.New("docker error"),
	}

	err := Stop(f, d, "abcd")
	assert.Error(t, err)
}
