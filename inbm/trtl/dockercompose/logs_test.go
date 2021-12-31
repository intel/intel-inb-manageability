package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestLogsSuccess(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := Logs(f, "--tail=4", "simple-compose", "web")
	assert.NoError(t, err)
}

func TestLogsFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error listing"),
		Output: []byte("inb"),
	}

	err := Logs(f, "--tail=4", "simple-compose", "web")
	assert.Error(t, err)
}
