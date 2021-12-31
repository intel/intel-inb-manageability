package realdocker

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadImageSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return nil
	}

	err := Load(f, d, name, "ref", 30)
	assert.NoError(t, err)
}

func TestLoadImageErrorFailsToOpen(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return nil
	}
	err := Load(f, d, namebad, "ref", 30)
	assert.Error(t, err)
}

func TestLoadImageReturnAnyDockerErrors(t *testing.T) {
	d := FakeDockerWrapper{
		Err: errors.New("error loading image"),
	}

	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return nil
	}

	err := Load(f, d, name, "ref", 30)
	assert.Error(t, err)
}

func TestLoadImageErrorFailsToLoad(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
		return errors.New("cannot find image")
	}
	err := Load(f, d, name, "ref", 30)
	assert.Error(t, err)
}
