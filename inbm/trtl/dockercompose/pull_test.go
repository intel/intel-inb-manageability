package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestPullSuccessfully(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := Pull(f, "inb")
	assert.NoError(t, err)
}

func TestImagePullFailsWithEmptyInstance(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := Pull(f, "")
	assert.Error(t, err)
}

func TestImagePullFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error starting docker-compose file"),
		Output: []byte("inb"),
	}

	unTar = func(cw util.ExecCommandWrapper, filename string, dir string) error {
		return nil
	}

	err := Pull(f, "inb")
	assert.Error(t, err)
}
