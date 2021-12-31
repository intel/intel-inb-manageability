package realdocker

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCorrectExitStatusWhenUnableToPull(t *testing.T) {
	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	oldOsExit := osExit
	defer func() {
		osExit = oldOsExit
	}()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	err := ImagePull(f, d, "ref", "auth", 30)
	assert.NoError(t, err)
	assert.Equal(t, 2, got)
}

func TestPullPublicImageSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return nil
	}

	err := ImagePull(f, d, "ref", "", 30)
	assert.NoError(t, err)
}

func TestReturnAnyDockerErrorsPullImage(t *testing.T) {
	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	d := FakeDockerWrapper{
		Err: errors.New("error importing image"),
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return nil
	}

	err := ImagePull(f, d, "ref", "", 30)
	assert.Error(t, err)
}
