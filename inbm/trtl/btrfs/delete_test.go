package btrfs

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestReturnNoErrorOnSnapshotDelete(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := DeleteSnapshot(f, "rootConfig", 2)
	assert.NoError(t, err)
}

func TestReturnsErrorOnSnapshotDelete(t *testing.T) {
	f := util.FakeCommandExec{
		Err: errors.New("error"),
	}
	err := DeleteSnapshot(f, "rootConfig", 2)
	assert.Error(t, err)
}
