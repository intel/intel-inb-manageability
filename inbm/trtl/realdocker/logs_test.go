package realdocker

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRetrieveLogContainerSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	err := Logs(f, d, ContainerLogOptions{}, "busybox")
	assert.NoError(t, err)
}

func TestErrorFindingContainerFails(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: true,
		Err:     errors.New("unable to find container"),
	}

	err := Logs(f, d, ContainerLogOptions{}, "busybox")
	assert.Error(t, err)
}

func TestUnableToFindContainerFails(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: false,
		Err:     nil,
	}

	err := Logs(f, d, ContainerLogOptions{}, "busybox")
	assert.Error(t, err)
}
