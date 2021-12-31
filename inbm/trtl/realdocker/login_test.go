package realdocker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	_, err := Login(d, "abcd", "server")
	assert.NoError(t, err)
}

func TestLoginErrors(t *testing.T) {
	d := FakeDockerWrapper{
		Err: errors.New("authentication error"),
	}

	_, err := Login(d, "abcd", "server")
	assert.Error(t, err)
}
