package btrfs

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
	"iotg-inb/trtl/util"
)

func TestPrepareConfigReturnsErrorWhenConfigDoesNotExist(t *testing.T) {
	f := util.FakeCommandExec{
		Output: []byte(unknownConfig),
		Err:    errors.New("error"),
	}

	cConfig = func(util.ExecCommandWrapper, string) error {
		return errors.New("error")
	}

	err := prepareConfig(f, "bla")
	assert.Error(t, err)
}

func TestPrepareConfigWhenConfigNotExistDefaultListNoErr(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	cConfig = func(util.ExecCommandWrapper, string) error {
		return nil
	}

	dList = func(util.ExecCommandWrapper, string) error {
		return nil
	}

	err := prepareConfig(f, "rootConfig")
	assert.NoError(t, err)
}

func TestPrepareConfigWhenConfigNotExistDefaultListErr(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("config file does not exist"),
		Output: []byte("Unknown config.\n"),
	}

	cConfig = func(util.ExecCommandWrapper, string) error {
		return nil
	}

	dList = func(util.ExecCommandWrapper, string) error {
		return errors.New("error")
	}

	err := prepareConfig(f, "rootConfig")
	assert.Error(t, err)
}

func TestPrepareConfigReturnsErrorWhenIsConfigErrors(t *testing.T) {
	f := util.FakeCommandExec{
		Err: errors.New("isConfig errors"),
	}

	err := prepareConfig(f, "bla")
	assert.Error(t, err)
}

func TestHelperProcessWithStd(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	fmt.Fprintf(os.Stdout, os.Getenv("STDOUT"))
	i, _ := strconv.Atoi(os.Getenv("EXIT_STATUS"))
	os.Exit(i)
}

// unit test
func TestReturnFalseOnUnknownConfig(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("unknown config"),
		Output: []byte(unknownConfig),
	}

	exist, err := isConfigExist(f, "rootConfig")
	assert.False(t, exist)
	assert.NoError(t, err)
}

func TestIsConfigExistReturnsNoError(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	exist, err := isConfigExist(f, "rootConfig")
	assert.NoError(t, err)
	assert.True(t, exist)
}

func TestIsConfigExistReturnsError(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("unable to find file"),
		Output: []byte("bla"),
	}

	exist, err := isConfigExist(f, "rootConfig")
	assert.Error(t, err)
	assert.False(t, exist)
}

func TestSetDefaultHelperReturnsNoError(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := setDefaultHelper(f, "rootConfig")
	assert.NoError(t, err)
}

func TestSetDefaultHelperReturnsError(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error"),
		Output: []byte("error"),
	}

	err := setDefaultHelper(f, "rootConfig")
	assert.Error(t, err)
}

func TestSetDefaultConfigReturnsNoError(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}

	err := setDefaultConfig(f, "rootConfig", "BACKGROUND_COMPARISON=no")
	assert.NoError(t, err)
}

func TestSetDefaultConfigReturnsError(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error"),
		Output: []byte("bla"),
	}

	err := setDefaultConfig(f, "rootConfig", "BACKGROUND_COMPARISON=no")
	assert.Error(t, err)
}

func TestCreateConfigReturnsNoError(t *testing.T) {
	f := util.FakeCommandExec{
		Err: nil,
	}
	err := createConfig(f, "rootConfig")
	assert.NoError(t, err)
}

func TestCreateConfigReturnsError(t *testing.T) {
	f := util.FakeCommandExec{
		Err:    errors.New("error"),
		Output: []byte("bla"),
	}

	err := createConfig(f, "rootConfig")
	assert.Error(t, err)
}
