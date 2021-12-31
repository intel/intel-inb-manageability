package realdocker

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
)

const name = "src/c"
const namebad = "src/d"

func TestCopyToContainerSuccessfully(t *testing.T) {
	f := FakeFinder{
		Err:       nil,
		Container: types.Container{ID: "abcd"},
		IsFound:   true,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := CopyToContainer(f, d, "abcd", name, name)
	assert.NoError(t, err)
}

func TestCopyToContainerErrorFailsToOpen(t *testing.T) {
	f := FakeFinder{
		Err:       nil,
		Container: types.Container{ID: "abcd"},
		IsFound:   true,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := CopyToContainer(f, d, "abcd", namebad, namebad)
	assert.Error(t, err)
}

func TestCopyToContainerErrorsFindingContainer(t *testing.T) {
	f := FakeFinder{
		IsFound: false,
		Err:     errors.New("unable to find container"),
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := CopyToContainer(f, d, "abcd", name, name)
	assert.Error(t, err)
}

func TestCopyToContainerErrorsNoContainerFound(t *testing.T) {
	f := FakeFinder{
		IsFound: false,
		Err:     nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := CopyToContainer(f, d, "abcd", name, name)
	assert.Error(t, err)
}

func TestCopyToContainerReturnAnyDockerErrors(t *testing.T) {
	f := FakeFinder{
		Err:       nil,
		Container: types.Container{ID: "abcd"},
		IsFound:   true,
	}

	d := FakeDockerWrapper{
		Err: errors.New("error copying to container"),
	}

	err := CopyToContainer(f, d, "abcd", name, name)
	assert.Error(t, err)
}
