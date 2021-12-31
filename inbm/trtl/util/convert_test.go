package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConvertStringToInteger(t *testing.T) {
	assert.Equal(t, 3, ConvertToInt("3"))
}

func TestExitOnNonIntegerParsing(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}

	osExit = myExit
	ConvertToInt("hello")
	assert.Equal(t, 1, got)
}
