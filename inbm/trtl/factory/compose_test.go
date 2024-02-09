package factory

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

var mockedExitStatus = 0
var mockedStdout string
var mockedStderr string

func TestReturnNilRegistrySafe(t *testing.T) {
	assert.Equal(t, isRegistryCredentialsSafe("username", "servername"), nil)}

func TestReturnErrorUserNameTooLong(t *testing.T) {
	expected := errors.New("error: docker registry username can not exceed 30 characters")
	actual := isRegistryCredentialsSafe("usernameusernameusernameusername", "servername")
	if actual.Error() != expected.Error() {
		t.Errorf("wrong error: %v", actual)
	}
}

func TestReturnErrorServerNameTooLong(t *testing.T) {
	expected := errors.New("error: docker registry servername can not exceed 253 characters")
	actual := isRegistryCredentialsSafe("username", 
	"servernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservernameservername")
	if actual.Error() != expected.Error() {
		t.Errorf("wrong error: %v", actual)
	}
}

func TestReturnErrorServerNameInvalid(t *testing.T) {
	expected := errors.New("error: no special characters allowed in username/registry. List of good characters include: [a-z], [A-Z], [0-9], . , - , _, : ")
	actual := isRegistryCredentialsSafe("username", "^servername")
	if actual.Error() != expected.Error() {
		t.Errorf("wrong error: %v", actual)
	}
}

func fakeComposeLogsSuccess(util.ExecCommandWrapper, string, string, string) error {
	return nil
}

func TestLogsExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composeLogs
	defer func() { composeLogs = old }()
	composeLogs = fakeComposeLogsSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Logs("simple-compose", "--tail=4", "web")
	assert.Equal(t, 0, got)
}

func fakeComposeLogsError(util.ExecCommandWrapper, string, string, string) error {
	return errors.New("error performing Docker Compose action")
}

func TestLogsExitsWithErrorCode(t *testing.T) {
	old := composeLogs
	defer func() { composeLogs = old }()
	composeLogs = fakeComposeLogsError

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Logs("simple-compose", "--tail=4", "web")
	assert.Equal(t, 1, got)
}

func TestUpExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composeUp
	defer func() { composeUp = old }()
	composeUp= fakeComposeSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Up("instanceName")
	assert.Equal(t, 0, got)
}

func TestUpExitsWithErrorCode(t *testing.T) {
	old := composeUp
	defer func() { composeUp = old }()
	composeUp = fakeComposeError

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Up("instanceName")
	assert.Equal(t, 1, got)
}

func fakeComposeSuccess(util.ExecCommandWrapper, string) error {
	return nil
}

func TestDownExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composeDown
	defer func() { composeDown = old }()
	composeDown = fakeComposeSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Down("instanceName")
	assert.Equal(t, 0, got)
}

func fakeComposeError(util.ExecCommandWrapper, string) error {
	return errors.New("error performing Docker Compose action")
}

func TestDownExitsWithErrorCode(t *testing.T) {
	old := composeDown
	defer func() { composeDown= old }()
	composeDown = fakeComposeError

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Down("instanceName")
	assert.Equal(t, 1, got)
}

func TestListExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composeList
	defer func() { composeList = old }()
	composeList = fakeComposeSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).List("instanceName")
	assert.Equal(t, 0, got)
}

func TestImageRemoveAllExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composeImagesRemoveAll
	defer func() { composeImagesRemoveAll = old }()
	composeImagesRemoveAll = fakeComposeSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).ImageRemoveAll("n", false)
	assert.Equal(t, 0, got)
}

func TestImageRemoveAllExitsWithErrorCode(t *testing.T) {
	old := composeImagesRemoveAll
	defer func() { composeImagesRemoveAll = old }()
	composeImagesRemoveAll = fakeComposeError

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).ImageRemoveAll("instanceName", false)
	assert.Equal(t, 1, got)
}

func TestImagePullExitsWithZeroExitCodeOnSuccess(t *testing.T) {
	old := composePull
	defer func() { composePull = old }()
	composePull = fakeComposeSuccess

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Pull("refString")
	assert.Equal(t, 0, got)
}

func TestPullExitsWithErrorCode(t *testing.T) {
	old := composePull
	defer func() { composePull = old }()
	composePull = fakeComposeError

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Pull("refString")
	assert.Equal(t, 1, got)
}

// This test is to force a test to be written in the event this method is implemented.
func TestLoginNotSupportedExitCode(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(ComposeInfo).Login("name", "server")
	assert.Equal(t, 1, got)
}
