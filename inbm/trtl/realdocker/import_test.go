package realdocker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCorrectExitStatusWhenUnableToImport(t *testing.T) {
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

	err := ImageImport(f, d, "ref", "src", 30, false)
	assert.NoError(t, err)
	assert.Equal(t, 2, got)
}

func TestImportImageSuccessfully(t *testing.T) {
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

	err := ImageImport(f, d, "ref", "src", 30, true)
	assert.NoError(t, err)
}

func TestReturnAnyDockerErrorsImageImport(t *testing.T) {
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

	err := ImageImport(f, d, "ref", "src", 30, true)
	assert.Error(t, err)
}
