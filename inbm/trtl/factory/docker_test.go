package factory

import (
	"errors"
	"github.com/docker/docker/api/types/registry"
	"testing"

	"github.com/stretchr/testify/assert"
	"iotg-inb/trtl/realdocker"
)

func TestErrorWhenGetLatestTagContainsAsterisk(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	new(DockerInfo).GetLatestTag("bla*")
	assert.Equal(t, 1, got)
}

func fakeListContainer(realdocker.DockerWrapper) error {
	return errors.New("error")
}

func TestExitCodeOnListContainersError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := listContainers
	defer func() { listContainers = old }()

	listContainers = fakeListContainer
	new(DockerInfo).List("")
	assert.Equal(t, 1, got)
}

func fakeLoad(realdocker.Finder, realdocker.DockerWrapper, string, string, int) error {
	return errors.New("error")
}

func TestExitCodeOnLoadError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := load
	defer func() { load = old }()

	load = fakeLoad
	new(DockerInfo).Load("src", "ref", 30)
	assert.Equal(t, 1, got)
}

func fakeCopyToContainer(realdocker.Finder, realdocker.DockerWrapper,
	string, string, string) error {
	return errors.New("error")
}

func TestExitCodeOnCopyToContainerError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := copyToContainer
	defer func() { copyToContainer = old }()

	copyToContainer = fakeCopyToContainer
	new(DockerInfo).ContainerCopy("source", "filename", "path")
	assert.Equal(t, 1, got)
}

func fakeRemoveContainer(realdocker.DockerWrapper, string, bool) error {
	return errors.New("error")
}

func TestExitCodeOnRemoveContainerByIDError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := removeContainer
	defer func() { removeContainer = old }()

	removeContainer = fakeRemoveContainer
	new(DockerInfo).ContainerRemoveByID("id", true)
	assert.Equal(t, 1, got)
}

func fakeRemoveAllContainers(realdocker.DockerWrapper, string, bool) error {
	return errors.New("error")
}

func TestExitCodeOnRemoveAllContainersError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := removeAllContainers
	defer func() { removeAllContainers = old }()

	removeAllContainers = fakeRemoveAllContainers
	new(DockerInfo).ContainerRemoveAll("name", true)
	assert.Equal(t, 1, got)
}

func fakeImageDeleteOld(realdocker.Finder, realdocker.DockerWrapper,
	int, string) error {
	return errors.New("error")
}

func TestExitCodeOnImageDeleteOldError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := imageDeleteOld
	defer func() { imageDeleteOld = old }()

	imageDeleteOld = fakeImageDeleteOld
	new(DockerInfo).ImageDeleteOld(3, "name")
	assert.Equal(t, 1, got)
}

func fakeImageImport(realdocker.Finder, realdocker.DockerWrapper, string,
	string, int, bool) error {
	return errors.New("error")
}

func TestExitCodeOnImageImportError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := imageImport
	defer func() { imageImport = old }()

	imageImport = fakeImageImport
	new(DockerInfo).ImageImport("refString", "source", 30, true)
	assert.Equal(t, 1, got)
}

func fakeImagePull(realdocker.Finder, realdocker.DockerWrapper, string, string, int) error {
	return errors.New("error")
}

func TestExitCodeOnImagePullError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := imagePull
	defer func() { imagePull = old }()

	imagePull = fakeImagePull
	new(DockerInfo).ImagePull("refString", "user", 30)
	assert.Equal(t, 1, got)
}

func fakeRemoveImage(realdocker.DockerWrapper, string, bool) error {
	return errors.New("error")
}

func TestExitCodeOnRemoveImageError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := removeImage
	defer func() { removeImage = old }()

	removeImage = fakeRemoveImage
	new(DockerInfo).ImageRemove("abcd", 1, true)
	assert.Equal(t, 1, got)
}

func fakeRemoveAllImages(realdocker.DockerWrapper, string, bool) error {
	return errors.New("error")
}

func TestExitCodeOnRemoveAllImagesError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := removeAllImages
	defer func() { removeAllImages = old }()

	removeAllImages = fakeRemoveAllImages
	new(DockerInfo).ImageRemoveAll("abcd", true)
	assert.Equal(t, 1, got)
}

func fakeGetImageByContainerId(realdocker.DockerWrapper, string) (string, string, error) {
	return "def", "def-name", errors.New("error")
}

func TestExitCodeOnGetImageByContainerIdError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := getImageByContainerId
	defer func() { getImageByContainerId = old }()

	getImageByContainerId = fakeGetImageByContainerId
	new(DockerInfo).GetImageByContainerId("abc")
	assert.Equal(t, 1, got)
}

func fakeRemoveLatestContainerFromImage(realdocker.Finder,
	realdocker.DockerWrapper, string, bool) error {
	return errors.New("error")
}

func TestExitCodeOnRemoveLatestContainerFromImageError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := removeLatestContainerFromImage
	defer func() { removeLatestContainerFromImage = old }()

	removeLatestContainerFromImage = fakeRemoveLatestContainerFromImage
	new(DockerInfo).ContainerRemove("name", 1, true)
	assert.Equal(t, 1, got)
}

func fakeStop(realdocker.Finder, realdocker.DockerWrapper, string) error {
	return errors.New("error")
}

func TestExitCodeOnStopError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := stop
	defer func() { stop = old }()

	stop = fakeStop
	new(DockerInfo).Stop("name", 1)
	assert.Equal(t, 1, got)
}

func fakeStopAll(realdocker.DockerWrapper, string) error {
	return errors.New("error")
}

func TestExitCodeOnStopAllError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := stopAll
	defer func() { stopAll = old }()

	stopAll = fakeStopAll
	new(DockerInfo).StopAll("name")
	assert.Equal(t, 1, got)
}

func fakeLogin(realdocker.DockerWrapper, string, string) (registry.AuthenticateOKBody, error) {
	return registry.AuthenticateOKBody{}, errors.New("error")
}

func TestExitCodeOnLoginError(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	old := login
	defer func() { login = old }()

	login = fakeLogin
	new(DockerInfo).Login("name", "server")
	assert.Equal(t, 1, got)
}
