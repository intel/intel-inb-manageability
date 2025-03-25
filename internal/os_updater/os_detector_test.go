package osupdater

import (
    "errors"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestDetectOS(t *testing.T) {
    originalExecCommand := execCommand
    originalGetOS := getOS
    defer func() {
        execCommand = originalExecCommand
        getOS = originalGetOS
    }()

    t.Run("detects Ubuntu OS", func(t *testing.T) {
        getOS = func() string { return "linux" }
        execCommand = func(name string, arg ...string) ([]byte, error) {
            return []byte("Distributor ID: Ubuntu\n"), nil
        }

        os, err := DetectOS()
        assert.NoError(t, err)
        assert.Equal(t, "Ubuntu", os)
    })

    t.Run("detects EMT OS", func(t *testing.T) {
        getOS = func() string { return "linux" }
        execCommand = func(name string, arg ...string) ([]byte, error) {
            return []byte("Distributor ID: microvisor\n"), nil
        }

        os, err := DetectOS()
        assert.NoError(t, err)
        assert.Equal(t, "EMT", os)
    })

    t.Run("unsupported OS type", func(t *testing.T) {
        getOS = func() string { return "Windows" }

        os, err := DetectOS()
        assert.Error(t, err)
        assert.Equal(t, "", os)
        assert.Equal(t, "unsupported OS type detected", err.Error())
    })

    t.Run("error detecting Linux distribution", func(t *testing.T) {
        getOS = func() string { return "linux" }
        execCommand = func(name string, arg ...string) ([]byte, error) {
            return nil, errors.New("command error")
        }

        os, err := DetectOS()
        assert.Error(t, err)
        assert.Equal(t, "", os)
        assert.Equal(t, "command error", err.Error())
    })
}

func TestGetOSType(t *testing.T) {
    originalGetOS := getOS
    defer func() {
        getOS = originalGetOS
    }()

    t.Run("returns linux for linux OS", func(t *testing.T) {
        getOS = func() string { return "linux" }
        assert.Equal(t, linux, getOSType())
    })

    t.Run("returns unsupportedOS for unsupported OS", func(t *testing.T) {
        getOS = func() string { return "unsupported" }
        assert.Equal(t, unsupportedOS, getOSType())
    })
}
