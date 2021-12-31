package btrfs

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/util"
)

// unit test
func TestReturnFalseWhenNoSnapper(t *testing.T) {
	f := util.FakeCommandExec{
		Err: errors.New("snapper not on system"),
	}

	exists := isSnapperOnSystem(f)
	assert.False(t, exists)
}

func TestTrueWhenSnapperExists(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	exists := isSnapperOnSystem(f)
	assert.True(t, exists)
}
