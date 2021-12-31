package realdocker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventsError(t *testing.T) {
	errChan := make(chan error, 1)
	errChan <- errors.New("error running command")
	d := FakeDockerWrapper{
		Err:         nil,
		ErrorChan:   errChan,
		MessageChan: nil,
	}

	err := Events(d)
	assert.Error(t, err)
}
