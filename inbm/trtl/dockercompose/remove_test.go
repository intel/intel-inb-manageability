package dockercompose

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

func TestRemoveAllImagesSuccess(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := ImageRemoveAll(f, "inb")
	assert.NoError(t, err)
}

func TestRemoveAllImagesFails(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error stopping image"),
		Output: []byte("inb"),
	}

	err := ImageRemoveAll(f, "inb")
	assert.Error(t, err)
}
