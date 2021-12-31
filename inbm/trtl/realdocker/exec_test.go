package realdocker

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExecSuccessful(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	err := Exec(d, "containerId", []string{""})

	assert.NoError(t, err)
}

func TestExecSendsErrorOnFailure(t *testing.T) {
	d := FakeDockerWrapper{
		Err: errors.New("error executing command"),
	}

	err := Exec(d, "containerId", []string{""})

	assert.Error(t, err)
}
