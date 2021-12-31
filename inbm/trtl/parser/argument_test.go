package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"iotg-inb/trtl/factory"
)

func TestReturnCorrectContainerType(t *testing.T) {
	c, err := ValidateBoxType("docker")
	assert.Equal(t, factory.Docker, c)
	assert.NoError(t, err)
}

func TestReturnNoneForInvalidBox(t *testing.T) {
	c, err := ValidateBoxType("bla")
	assert.Equal(t, factory.None, c)
	assert.Error(t, err, "unrecognized box type")
}

func TestReturnNoneForMissingBox(t *testing.T) {
	c, err := ValidateBoxType("")
	assert.Equal(t, factory.None, c)
	assert.Error(t, err, "box type parameter was empty")
}

func TestReturnCorrectDockerCommand(t *testing.T) {
	c, err := ValidateCommandType("stopall", "docker")
	assert.Equal(t, StopAll, c)
	assert.NoError(t, err)
}

func TestReturnCorrectBtrfsCommand(t *testing.T) {
	c, err := ValidateCommandType("list", "btrfs")
	assert.Equal(t, List, c)
	assert.NoError(t, err)
}

func TestReturnNoneForInvalidBtrfsCommand(t *testing.T) {
	c, err := ValidateCommandType("stopall", "btrfs")
	assert.Equal(t, noCommand, c)
	assert.EqualError(t, err, "unrecognized command type for btrfs")
}

func TestReturnNoneForInvalidDockerCommand(t *testing.T) {
	c, err := ValidateCommandType("bla", "docker")
	assert.Equal(t, noCommand, c)
	assert.Error(t, err, "unrecognized command type for docker")
}

func TestReturnNoneForMissingCommand(t *testing.T) {
	c, err := ValidateCommandType("", "docker")
	assert.Equal(t, noCommand, c)
	assert.Error(t, err, "command parameter was empty")
}

func TestReturnTrueForValueInArray(t *testing.T) {
	arrayNames := []string{"bird", "cat", "dog"}
	if !InArray("cat", arrayNames) {
		t.Error("Expected true for value in array.")
	}
}

func TestReturnFalseForValueNotInArray(t *testing.T) {
	arrayNames := []string{"bird", "cat", "dog"}
	if InArray("horse", arrayNames) {
		t.Error("Expected false for value not in array.")
	}
}
