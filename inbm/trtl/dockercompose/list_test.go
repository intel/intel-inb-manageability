package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestListSuccess(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := List(f, "inb")
	assert.NoError(t, err)
}

func TestListFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error listing"),
		Output: []byte("inb"),
	}

	err := List(f, "inb")
	assert.Error(t, err)
}
