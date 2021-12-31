package factory

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestPreSnapshotReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	single = func(util.ExecCommandWrapper, string, string) error {
		return errors.New("exact error")
	}
	new(SnapperInfo).SingleSnapshot("rootConfig", "sota_update")
	assert.Equal(t, 1, got)
}

func TestPreSnapshotReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	single = func(util.ExecCommandWrapper, string, string) error {
		return nil
	}
	new(SnapperInfo).SingleSnapshot("rootConfig", "sota_update")
	assert.Equal(t, 0, got)
}

func TestUndoChangeReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	undo = func(util.ExecCommandWrapper, string, int) error {
		return errors.New("exact error")
	}
	new(SnapperInfo).UndoChange("rootConfig", 1)
	assert.Equal(t, 1, got)
}

func TestUndoChangeReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	undo = func(util.ExecCommandWrapper, string, int) error {
		return nil
	}
	new(SnapperInfo).UndoChange("rootConfig", 1)
	assert.Equal(t, 0, got)
}

func TestDeleteSnapshotReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	delete = func(util.ExecCommandWrapper, string, int) error {
		return errors.New("error")
	}
	new(SnapperInfo).DeleteSnapshot("rootConfig", 1)
	assert.Equal(t, 1, got)
}

func TestDeleteSnapshotReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	delete = func(util.ExecCommandWrapper, string, int) error {
		return nil
	}
	new(SnapperInfo).DeleteSnapshot("rootConfig", 1)
	assert.Equal(t, 0, got)
}

// This test is to ensure unit tests are created once List is implemented.
func TestListNotSupportedErrorCode(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(SnapperInfo).List("")
	assert.Equal(t, 3, got)
}
