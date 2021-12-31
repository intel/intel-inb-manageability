package realdocker

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
)

// TODO: This is technically an integration test because it calls stop/start
func TestDockerIntegrationAll(t *testing.T) {
	df := DockerFinder{}
	dw := DockerWrap{}

	s, err := NewInstance(0, "hello-world", nil).Snapshot(df, dw)
	if err != nil {
		t.Error(err)
	}

	_, err = s.Instantiate(ContainerOptions{}, []string{})
	assert.NoError(t, err)

	s2, err := s.Snapshot(df, dw)
	assert.NoError(t, err)

	_, err = s2.Instantiate(ContainerOptions{}, []string{})
	assert.NoError(t, err)

	_, err = s2.Start(df, dw, ContainerOptions{}, []string{})
	assert.NoError(t, err)

	if err = StopAll(dw, "hello-world"); err != nil {
		t.Fatal("Unable to stop all hello-world containers:", err)
	}
	if err = RemoveAllContainers(dw, "", true); err != nil {
		t.Fatal("Unable to remove all hello-world containers:", err)
	}

	// TODO:  Should add RemoveAll, but there are issues when TC is not clean from other tests.
}

func TestRemoveAllContainersSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd", RepoTags: []string{"abcd"}},
		},
	}

	err := RemoveAllContainers(d, "abcd", false)
	assert.NoError(t, err)
}

func TestRemoveImageSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	err := RemoveImage(d, "abcd", true)
	assert.NoError(t, err)
}

func TestRemoveImageReturnAnyDockerErrors(t *testing.T) {
	d := FakeDockerWrapper{
		Err: errors.New("error removing image"),
	}

	err := RemoveImage(d, "abcd", true)
	assert.Error(t, err)
}

func TestRemoveAllImagesSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd", RepoTags: []string{"abcd"}},
		},
	}

	err := RemoveAllImages(d, "abcd", true)
	assert.NoError(t, err)
}

func TestRemoveAllImagesReturnsErrorWhenNoImages(t *testing.T) {
	d := FakeDockerWrapper{
		Err:    nil,
		Images: []types.ImageSummary{},
	}

	err := RemoveAllImages(d, "abcd", true)
	assert.Error(t, err)
}

func TestRemoveAllImagesReturnsAnyDockerErrors(t *testing.T) {
	d := FakeDockerWrapper{
		Err:    errors.New("error removing all images"),
		Images: []types.ImageSummary{},
	}

	err := RemoveAllImages(d, "abcd", true)
	assert.Error(t, err)
}

func TestRemoveLatestContainerFromImageSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err:    nil,
		Images: []types.ImageSummary{},
	}

	err := RemoveLatestContainerFromImage(f, d, "abcd", true)
	assert.NoError(t, err)
}

func TestRemoveLatestContainerErrorWhenFindingContainer(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       errors.New("error finding container"),
	}

	d := FakeDockerWrapper{
		Err:    nil,
		Images: []types.ImageSummary{},
	}

	err := RemoveLatestContainerFromImage(f, d, "abcd", true)
	assert.Error(t, err)
}

func TestRemoveLatestContainerErrorWhenNoContainerFound(t *testing.T) {
	f := FakeFinder{
		IsFound:   false,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err:    nil,
		Images: []types.ImageSummary{},
	}

	err := RemoveLatestContainerFromImage(f, d, "abcd", true)
	assert.Error(t, err)
}

func TestRemoveLatestContainerReturnsAnyDockerErrors(t *testing.T) {
	f := FakeFinder{
		IsFound:   true,
		Container: types.Container{ID: "abcd"},
		Err:       nil,
	}

	d := FakeDockerWrapper{
		Err:    errors.New("docker error"),
		Images: []types.ImageSummary{},
	}

	err := RemoveLatestContainerFromImage(f, d, "abcd", true)
	assert.Error(t, err)
}
