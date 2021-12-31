package main

import (
	"errors"
	"iotg-inb/trtl/factory"
	"iotg-inb/trtl/parser"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReturnTrueOnValidInput(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit
	validateStringInput("Testing")
	assert.NotEqual(t, 1, got)
}

func TestExitOnNullCharacterInput(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit
	validateStringInput("Test\x00ing")
	assert.Equal(t, 1, got)
}

func TestReturnMaxWhenOutOfBoundsValueGivenForImagesToKeep(t *testing.T) {
	assert.Equal(t, 4, verifyNumImagesKeptWithinLimits(6))
}

func TestReturnMinWhenOutOfBoundsValueGivenForImagesToKeep(t *testing.T) {
	assert.Equal(t, 1, verifyNumImagesKeptWithinLimits(0))
}

func TestReturnValueWhenInBoundsValueGivenForImagesToKeep(t *testing.T) {
	assert.Equal(t, 2, verifyNumImagesKeptWithinLimits(2))
}

func TestExitWhenOutOfBoundsValueGivenForWaitTime(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	verifyWaitTimeWithinLimits(301)
	assert.Equal(t, 1, got)
}

func fakeErrorParseSecurityOptions(o string) (factory.SecurityOptions, error) {
	return factory.SecurityOptions{AppArmor: "bla", SecComp: ""}, errors.New("error")
}

func TestExitCodeOnInvalidSecurityOptionParse(t *testing.T) {
	oldParse := parseSecurityOptions
	defer func() { parseSecurityOptions = oldParse }()
	parseSecurityOptions = fakeErrorParseSecurityOptions

	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	getSecurityOptions("security")
	assert.Equal(t, 1, got)
}

func fakeSuccessParseSecurityOptions(o string) (factory.SecurityOptions, error) {
	return factory.SecurityOptions{AppArmor: "bla", SecComp: ""}, nil
}

func TestReturnOptionsOnValidParse(t *testing.T) {
	oldParse := parseSecurityOptions
	defer func() { parseSecurityOptions = oldParse }()
	parseSecurityOptions = fakeSuccessParseSecurityOptions

	o := getSecurityOptions("security")
	assert.Equal(t, []string([]string{"apparmor=bla", "seccomp="}), o)
}

func TestCreateCorrectBoxType(t *testing.T) {
	bb := createBox("docker")
	assert.Equal(t, reflect.TypeOf(new(factory.DockerInfo)), reflect.TypeOf(bb))
}

func TestExitCodeIncorrectBoxType(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	createBox("invalid")
	assert.Equal(t, 1, got)
}

func fakeErrorValidateBoxType(box string) (string, error) {
	return "bla", errors.New("error")
}

func TestExitCodeWhenInvalidBoxType(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	oldParseBoxType := parseBoxType
	defer func() { parseBoxType = oldParseBoxType }()
	parseBoxType = fakeErrorValidateBoxType
	validateBoxType("bla")

	assert.Equal(t, 1, got)
}

func fakeErrorValidateCommandType(cmdType string, boxType string) (string, error) {
	return "bla", errors.New("error")
}

func TestExitCodeWhenInvalidCmdType(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	oldParseCmdType := parseCmdType
	defer func() { parseCmdType = oldParseCmdType }()
	parseCmdType = fakeErrorValidateCommandType
	validateCommandType("cmd", "box")

	assert.Equal(t, 1, got)
}

func TestReturnTrueOnValidString(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit
	validateStringFlag("test", "valid")
	assert.NotEqual(t, 1, got)
}

func TestReturnExitCodeOnInvalidString(t *testing.T) {
	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit
	validateStringFlag("test", "")
	assert.Equal(t, 1, got)
}

func TestReturnTrueOnValidInt(t *testing.T) {
	assert.True(t, validateIntFlag("test", 1))
}

func TestReturnExitCodeOnInvalidInteger(t *testing.T) {
	oldOsExit := osExit
	defer func() { osExit = oldOsExit }()

	var got int
	myExit := func(code int) {
		got = code
	}
	osExit = myExit

	validateIntFlag("test", -1)
	assert.Equal(t, 1, got)
}

func TestReturnDockerForValidBoxType(t *testing.T) {
	assert.Equal(t, "docker", validateBoxType("docker"))
}

func TestReturnCorrectCommandType(t *testing.T) {
	assert.Equal(t, parser.List, validateCommandType("List", "Btrfs"))
}

func fakeErrorParseValue(filePath string, valuePath parser.ConfigValue) (string, error) {
	return "3", errors.New("error")
}

func TestGetsDefaultMaxWaitTimeValueOnError(t *testing.T) {
	oldParseValue := parseValue
	defer func() { parseValue = oldParseValue }()
	parseValue = fakeErrorParseValue
	assert.Equal(t, 180, getMaxWaitTime())
}

func fakeSuccessParseValue(filePath string, valuePath parser.ConfigValue) (string, error) {
	return "150", nil
}

func TestGetsCorrectMaxWaitTimeValue(t *testing.T) {
	oldParseValue := parseValue
	defer func() { parseValue = oldParseValue }()
	parseValue = fakeSuccessParseValue
	assert.Equal(t, 150, getMaxWaitTime())
}
