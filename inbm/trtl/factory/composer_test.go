package factory

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestDownReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	down = func(util.ExecCommandWrapper, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).Down("tc")
	assert.Equal(t, 1, got)
}

func TestReturnTrueUsernameRegistrySafe(t *testing.T) {
	assert.True(t, isRegistryCredentialsSafe("username", "servername"))
}

func TestReturnFalseUserNameTooLong(t *testing.T) {
	assert.False(t, isRegistryCredentialsSafe("usernameusernameusernameusername", "servername"))
}

func TestReturnFalseServerNameTooLong(t *testing.T) {
	assert.False(t, isRegistryCredentialsSafe("username", 
	"servernameservernameservernameservernameservernameservernameservername"))
}

func TestDownReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	down = func(util.ExecCommandWrapper, string) error {
		return nil
	}
	new(ComposerInfo).Down("tc")
	assert.Equal(t, 0, got)
}

func TestUpReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	up = func(util.ExecCommandWrapper, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).Up("tc")
	assert.Equal(t, 1, got)
}

func TestUpReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	up = func(util.ExecCommandWrapper, string) error {
		return nil
	}
	new(ComposerInfo).Up("tc")
	assert.Equal(t, 0, got)
}

func TestUpWithFileReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	upWithFile = func(util.ExecCommandWrapper, string, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).UpWithFile("tc", "file.yml")
	assert.Equal(t, 1, got)
}

func TestUpWithFileReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	upWithFile = func(util.ExecCommandWrapper, string, string) error {
		return nil
	}
	new(ComposerInfo).UpWithFile("tc", "file.yml")
	assert.Equal(t, 0, got)
}

func TestPullReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	pull = func(util.ExecCommandWrapper, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).Pull("tc")
	assert.Equal(t, 1, got)
}

func TestPullReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	pull = func(util.ExecCommandWrapper, string) error {
		return nil
	}
	new(ComposerInfo).Pull("tc")
	assert.Equal(t, 0, got)
}

func TestPullWithFileReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	pullWithFile = func(util.ExecCommandWrapper, string, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).PullWithFile("tc", "file.yml")
	assert.Equal(t, 1, got)
}

func TestPullWithFileReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	pullWithFile = func(util.ExecCommandWrapper, string, string) error {
		return nil
	}
	new(ComposerInfo).PullWithFile("tc", "file.yml")
	assert.Equal(t, 0, got)
}

func TestDownWithFileReturnsExitCodeOnError(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	downWithFile = func(util.ExecCommandWrapper, string, string) error {
		return errors.New("exact error")
	}
	new(ComposerInfo).DownWithFile("tc", "file.yml")
	assert.Equal(t, 1, got)
}

func TestDownWithFileReturnsSuccess(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	downWithFile = func(util.ExecCommandWrapper, string, string) error {
		return nil
	}
	new(ComposerInfo).DownWithFile("tc", "file.yml")
	assert.Equal(t, 0, got)
}