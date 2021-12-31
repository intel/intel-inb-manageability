package realdocker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"iotg-inb/trtl/logging"
)

// TODO: This is technically an integration test because it calls Instantiate
func TestDockerCommit(t *testing.T) {
	instance := NewInstance(0, "hello-world", nil)
	logging.DebugLogLn("Attempting snapshot of", instance.GetImageTag())
	df := DockerFinder{}
	dw := DockerWrap{}
	s, err := instance.Snapshot(df, dw)
	assert.NoError(t, err)

	logging.DebugLogLn("Attempting to instantiate", s.GetImageTag())
	_, err = s.Instantiate(ContainerOptions{}, []string{})

	assert.NoError(t, err)
	assert.Equal(t, "hello-world", s.GetName())
	assert.Equal(t, 1, s.GetVersion())

	s2, err := s.Snapshot(df, dw)
	assert.NoError(t, err)

	_, err = s2.Instantiate(ContainerOptions{}, []string{})
	assert.NoError(t, err)

	err = s2.Commit(df, dw)
	assert.NoError(t, err)
}

func TestCommitErrorsFindingContainer(t *testing.T) {
	f := FakeFinder{
		IsFound: true,
		Err:     errors.New("unable to find container"),
	}

	i := NewInstance(1, "abcd", nil)

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := i.Commit(f, d)
	assert.Error(t, err)
}

func TestCommitErrorsNoContainerFound(t *testing.T) {
	f := FakeFinder{
		IsFound: false,
		Err:     nil,
	}

	i := NewInstance(1, "abcd", nil)

	d := FakeDockerWrapper{
		Err: nil,
	}

	err := i.Commit(f, d)
	assert.Error(t, err)
}
