package util

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnTarSuccess(t *testing.T) {
	f := FakeCommandExec{
		Err: nil,
	}

	err := UnTar(f, "inb", "dir")
	assert.NoError(t, err)
}

func TestUntarFails(t *testing.T) {
	f := FakeCommandExec{
		Err:    errors.New("error untarring file"),
		Output: []byte("inb"),
	}

	err := UnTar(f, "inb", "dir")
	assert.Error(t, err)
}
