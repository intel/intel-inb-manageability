package osupdater

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockExecutor struct {
    commands [][]string
    outputs  []string
    errors   []error
}

func (m *mockExecutor) Execute(command []string) ([]byte, error) {
    m.commands = append(m.commands, command)
    if len(m.outputs) > 0 {
        output := m.outputs[0]
        m.outputs = m.outputs[1:]
        return []byte(output), m.errors[0]
    }
    return nil, m.errors[0]
}

func TestUbuntuDownloader_Download(t *testing.T) {
    t.Run("successful download", func(t *testing.T) {
        downloader := &UbuntuDownloader{}
        err := downloader.Download()
        assert.NoError(t, err)
    })
}

func TestNoDownload(t *testing.T) {
    t.Run("no packages", func(t *testing.T) {
        expectedCmds := []string{
            "dpkg", "--configure", "-a",
            "--force-confdef",
            "--force-confold",
            "apt-get", "-o",
            "Dpkg::Options::='--force-confdef'", "-o",
            "Dpkg::Options::='--force-confold'", "-yq",
            "-f", "install",
            "apt-get", "-o", "Dpkg::Options::='--force-confdef'", 
			"-o", "Dpkg::Options::='--force-confold'", 
			"--with-new-pkgs", "--no-download", 
			"--fix-missing", "-yq", "upgrade",
        }

        cmds := noDownload([]string{})
        assert.Equal(t, expectedCmds, cmds)
    })

    t.Run("with packages", func(t *testing.T) {
        packages := []string{"package1", "package2"}
        expectedCmds := []string{
            "dpkg", "--configure", "-a",
            "--force-confdef",
            "--force-confold",
            "apt-get", "-o",
            "Dpkg::Options::='--force-confdef'", "-o",
            "Dpkg::Options::='--force-confold'", "-yq",
            "-f", "install",
            "apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--no-download", "--fix-missing", "-yq", "install", "package1", "package2",
        }

        cmds := noDownload(packages)
        assert.Equal(t, expectedCmds, cmds)
    })
}

func TestDownloadOnly(t *testing.T) {
    t.Run("no packages", func(t *testing.T) {
        expectedCmds := []string{
            "apt-get", "update", "dpkg-query", "-f", "-a", "'${binary:Package}\\n'", "-W",
            "apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "--download-only", "--fix-missing", "-yq", "upgrade",
        }

        cmds := downloadOnly([]string{})
        assert.Equal(t, expectedCmds, cmds)
    })

    t.Run("with packages", func(t *testing.T) {
        packages := []string{"package1", "package2"}
        expectedCmds := []string{
            "apt-get", "update", "dpkg-query", "-f", "-a", "'${binary:Package}\\n'", "-W",
            "apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--download-only", "--fix-missing", "-yq", "install", "package1", "package2",
        }

        cmds := downloadOnly(packages)
        assert.Equal(t, expectedCmds, cmds)
    })
}

func TestGetEstimatedSize(t *testing.T) {
    t.Run("no update available", func(t *testing.T) {
        mockExec := &mockExecutor{
            outputs: []string{"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."},
            errors:  []error{nil},
        }

        isUpdateAvail, size, err := getEstimatedSize(mockExec)
        assert.False(t, isUpdateAvail)
        assert.NoError(t, err)
        assert.Equal(t, int64(0), size)
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
    })

    t.Run("successful size estimation outside Docker", func(t *testing.T) {
        mockExec := &mockExecutor{
            outputs: []string{"After this operation, 500 MB of additional disk space will be used."},
            errors:  []error{nil},
        }

        isUpdateAvail, size, err := getEstimatedSize(mockExec)
        assert.NoError(t, err)
        assert.True(t, isUpdateAvail)
        assert.Equal(t, int64(524288000), size)
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
    })

    t.Run("failed to get size estimation", func(t *testing.T) {
         mockExec := &mockExecutor{
            outputs: []string{""},
            errors:  []error{errors.New("execution error")},
        }

        isUpdateAvail, size, err := getEstimatedSize(mockExec)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get size of the update")
        assert.True(t, isUpdateAvail)
        assert.Equal(t, int64(0), size)
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
    })

    t.Run("no size information in output", func(t *testing.T) {
        mockExec := &mockExecutor{
            outputs: []string{"No size information available."},
            errors:  []error{nil},
        }

        isUpdateAvail, size, err := getEstimatedSize(mockExec)
        assert.Contains(t, err.Error(), "failed to get size of the update")
        assert.False(t, isUpdateAvail)
        assert.Equal(t, int64(0), size)
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
    })
}

func TestSizeToBytes(t *testing.T) {
	tests := []struct {
		name     string
		size     string
		unit     string
		expected int64
	}{
		{
			name:     "Convert kB to bytes",
			size:     "1",
			unit:     "kB",
			expected: 1024,
		},
		{
			name:     "Convert MB to bytes",
			size:     "1",
			unit:     "MB",
			expected: 1024 * 1024,
		},
		{
			name:     "Convert GB to bytes",
			size:     "1",
			unit:     "GB",
			expected: 1024 * 1024 * 1024,
		},
		{
			name:     "Convert fractional GB to bytes",
			size:     "1.5",
			unit:     "GB",
			expected: int64(1.5 * 1024 * 1024 * 1024),
		},
		{
			name:     "No unit, assume bytes",
			size:     "1024",
			unit:     "",
			expected: 1024,
		},
		{
			name:     "Invalid size string",
			size:     "invalid",
			unit:     "MB",
			expected: 0,
		},
		{
			name:     "Zero size",
			size:     "0",
			unit:     "MB",
			expected: 0,
		},
		{
			name:     "Negative size",
			size:     "-1",
			unit:     "MB",
			expected: int64(-1 * 1024 * 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := sizeToBytes(tt.size, tt.unit)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetEstimatedSizeFromAptGetUpgrade(t *testing.T) {
    t.Run("successful size estimation", func(t *testing.T) {
        upgradeOutput := "After this operation, 500 MB of additional disk space will be used."
        expectedSize := int64(524288000)

        isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
        assert.NoError(t, err)
        assert.True(t, isUpdateAvail)
        assert.Equal(t, expectedSize, size)
    })

    t.Run("size estimation with commas", func(t *testing.T) {
        upgradeOutput := "After this operation, 1,000 MB of additional disk space will be used."
        expectedSize := int64(1048576000)

        isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
        assert.NoError(t, err)
        assert.True(t, isUpdateAvail)
        assert.Equal(t, expectedSize, size)
    })

    t.Run("size estimation with different units", func(t *testing.T) {
        upgradeOutput := "After this operation, 1.5 GB of additional disk space will be used."
        expectedSize := int64(1610612736)

        isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
        assert.NoError(t, err)
        assert.True(t, isUpdateAvail)
        assert.Equal(t, expectedSize, size)
    })

    t.Run("no size information", func(t *testing.T) {
        upgradeOutput := "No size information available."
        expectedSize := int64(0)

        isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get size of the update")
        assert.False(t, isUpdateAvail)
        assert.Equal(t, expectedSize, size)
    })

    t.Run("size estimation with freed space", func(t *testing.T) {
        upgradeOutput := "After this operation, 500 MB of disk space will be freed."
        expectedSize := int64(0)

        isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
        assert.NoError(t, err)
        assert.True(t, isUpdateAvail)
        assert.Equal(t, expectedSize, size)
    })
}

func TestUbuntuRebooter_Reboot(t *testing.T) {

    t.Run("successful reboot", func(t *testing.T) {
        mockExec := &mockExecutor{
            outputs: []string{""},
            errors:  []error{nil},
        }

        rebooter := &UbuntuRebooter{
            commandExecutor: mockExec,
        }

        err := rebooter.Reboot()
        assert.NoError(t, err)
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/sbin/reboot"}, mockExec.commands[0])
    })

      t.Run("failed reboot", func(t *testing.T) {
        mockExec := &mockExecutor{
            outputs: []string{""},
            errors:  []error{errors.New("reboot error")},
        }

        rebooter := &UbuntuRebooter{
            commandExecutor: mockExec,
        }

        err := rebooter.Reboot()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "SOTA Aborted: Reboot Failed")
        assert.Equal(t, 1, len(mockExec.commands))
        assert.Equal(t, []string{"/sbin/reboot"}, mockExec.commands[0])
    })
}
