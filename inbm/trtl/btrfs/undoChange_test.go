package btrfs

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestReturnNoErrorOnRollback(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := UndoChange(f, "rootConfig", 1)
	assert.NoError(t, err)
}

func TestReturnsErrorOnRollback(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error"),
		Output: []byte("bla"),
	}

	err := UndoChange(f, "rootConfig", 1)
	assert.Error(t, err)
}
