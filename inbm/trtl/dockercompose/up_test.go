package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestUpWithFileSuccessfully(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := UpWithFile(f, "inb", "yml.file")
	assert.NoError(t, err)
}

func TestUpSuccessfully(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := Up(f, "inb")
	assert.NoError(t, err)
}

func TestUpDockerComposeFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error starting docker-compose file"),
		Output: []byte("inb"),
	}

	unTar = func(cw util.ExecCommandWrapper, filename string, dir string) error {
		return nil
	}

	err := Up(f, "inb")
	assert.Error(t, err)
}

