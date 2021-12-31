package btrfs

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

// unit test
func TestSnapshotSingleReturnsErrorWhenNoSnapper(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("no snapper"),
		Output: []byte("no snapper"),
	}

	err := SingleSnapshot(f, "rootConfig", "sota_update")
	assert.Error(t, err)
}

func TestSnapshotSingleReturnsErrorWhenPrepareConfigErrors(t *testing.T) {
	oldPrepareConfig := prepareConfig
	defer func() { pConfig = oldPrepareConfig }()

	pConfig = func(util.ExecCommandWrapper, string) error {
		return errors.New("error")
	}

	f := util.FakeCommandExec{
		Err: nil,
	}

	err := SingleSnapshot(f, "rootConfig", "sota_update")
	assert.Error(t, err)
}

func TestSingleSnapshotReturnsNoError(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := SingleSnapshot(f, "rootConfig", "sota_update")
	assert.NoError(t, err)
}

func TestSingleSnapshotExecCommandReturnsError(t *testing.T) {
	oldPrepareConfig := prepareConfig
	oldIsSnapper := isSnapper
	defer func() { isSnapper = oldIsSnapper }()
	defer func() { pConfig = oldPrepareConfig }()

	isSnapper = func(util.ExecCommandWrapper) bool {
		return true
	}

	pConfig = func(util.ExecCommandWrapper, string) error {
		return nil
	}

	f := util.FakeCommandExec{
		Err: errors.New("error"),
	}

	err := SingleSnapshot(f, "rootConfig", "sota_update")
	assert.Error(t, err)
}
