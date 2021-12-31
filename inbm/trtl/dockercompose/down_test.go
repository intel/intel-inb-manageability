package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestDownSuccess(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := Down(f, "inb")
	assert.NoError(t, err)
}

func TestStopFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error stopping image"),
		Output: []byte("inb"),
	}

	err := Down(f, "inb")
	assert.Error(t, err)
}
