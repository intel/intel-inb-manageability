/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package ubuntu updates the Ubuntu OS.
package ubuntu

import (
	"errors"
	"testing"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/stretchr/testify/assert"
)

type mockExecutor struct {
	commands [][]string
	stdout   []string
	stderr   []string
	errors   []error
}

func (m *mockExecutor) Execute(command []string) ([]byte, []byte, error) {
	m.commands = append(m.commands, command)
	var stdout, stderr string
	if len(m.stderr) > 0 {
		stderr = m.stderr[0]
		m.stderr = m.stderr[1:]
	}
	if len(m.stdout) > 0 {
		stdout = m.stdout[0]
		m.stdout = m.stdout[1:]
	}
	return []byte(stdout), []byte(stderr), m.errors[0]
}

func TestUbuntuDownloader_Download(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		downloader := &Downloader{}
		err := downloader.Download()
		assert.NoError(t, err)
	})
}

func TestNoDownload(t *testing.T) {
	t.Run("no packages", func(t *testing.T) {
		expectedCmds := [][]string{
			{"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"},
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef", "-o",
				"Dpkg::Options::=--force-confold", "-yq", "-f", "install"},
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold",
				"--with-new-pkgs",
				"--fix-missing", "-yq", "upgrade"},
		}

		cmds := noDownload([]string{})
		assert.Equal(t, 3, len(cmds))
		assert.Equal(t, expectedCmds, cmds)
	})

	t.Run("with packages", func(t *testing.T) {
		packages := []string{"package1", "package2"}
		expectedCmds := [][]string{
			{"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"},
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef", "-o",
				"Dpkg::Options::=--force-confold", "-yq", "-f", "install"},
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold",
				"--fix-missing", "-yq",
				"install", "package1", "package2"},
		}

		cmds := noDownload(packages)
		assert.Equal(t, 3, len(cmds))
		assert.Equal(t, expectedCmds, cmds)
	})
}

func TestDownloadOnly(t *testing.T) {
	t.Run("no packages", func(t *testing.T) {
		expectedCmds := [][]string{
			{"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"},
			{"apt-get", "update"},			
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold",
				"--with-new-pkgs", "--download-only", "--fix-missing",
				"-yq", "upgrade"},
		}

		cmds := downloadOnly([]string{})
		assert.Equal(t, 3, len(cmds))
		assert.Equal(t, expectedCmds, cmds)
	})

	t.Run("with packages", func(t *testing.T) {
		packages := []string{"package1", "package2"}
		expectedCmds := [][]string{
			{"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"},
			{"apt-get", "update"},
			{"apt-get", "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold",
				"--download-only", "--fix-missing",
				"-yq", "install", "package1", "package2"},
		}

		cmds := downloadOnly(packages)
		assert.Equal(t, expectedCmds, cmds)
	})
}

func TestGetEstimatedSize(t *testing.T) {
	t.Run("no update available", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."},
			errors: []error{nil},
		}

		isUpdateAvail, size, err := GetEstimatedSize(mockExec)
		assert.False(t, isUpdateAvail)
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), size)
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
	})

	t.Run("successful size estimation", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{"After this operation, 500 MB of additional disk space will be used."},
			stderr: []string{""},
			errors: []error{nil},
		}

		isUpdateAvail, size, err := GetEstimatedSize(mockExec)
		assert.NoError(t, err)
		assert.True(t, isUpdateAvail)
		assert.Equal(t, uint64(524288000), size)
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
	})

	t.Run("failed to get size estimation", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{""},
			errors: []error{errors.New("execution error")},
		}

		isUpdateAvail, size, err := GetEstimatedSize(mockExec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get size of the update")
		assert.False(t, isUpdateAvail)
		assert.Equal(t, uint64(0), size)
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
	})

	t.Run("no size information in output", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{"No size information available."},
			errors: []error{nil},
		}

		isUpdateAvail, size, err := GetEstimatedSize(mockExec)
		assert.Contains(t, err.Error(), "failed to get size of the update")
		assert.False(t, isUpdateAvail)
		assert.Equal(t, uint64(0), size)
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::='--force-confdef'", "-o", "Dpkg::Options::='--force-confold'", "--with-new-pkgs", "-u", "upgrade", "--assume-no"}, mockExec.commands[0])
	})
}

func TestUbuntuUpdater_Update(t *testing.T) {
    t.Run("set environment variables successfully", func(t *testing.T) {
        mockExec := &mockExecutor{
			stdout: []string{""},
			stderr: []string{""},
			errors: []error{nil},
		}
        updater := &Updater{
            CommandExecutor: mockExec,
            Request:         &pb.UpdateSystemSoftwareRequest{
				Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD,
			},
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100000000, nil
			},
		}

        proceedWithReboot, err := updater.Update()
        assert.NoError(t, err)
		assert.True(t, proceedWithReboot)
    })

    // t.Run("fail to set environment variables", func(t *testing.T) {
	// 	originalSetenv := os.Setenv
    //     defer func() { os.Setenv = originalSetenv }()

    //     os.Setenv = func(key, value string) error {
    //         return errors.New("failed to set environment variable")
    //     }

    //     mockExec := &mockExecutor{}
    //     updater := &UbuntuUpdater{
    //         commandExecutor: mockExec,
    //         request:         &pb.UpdateSystemSoftwareRequest{},
    //     }

    //     err := updater.Update()
    //     assert.Error(t, err)
    //     assert.Contains(t, err.Error(), "Failed to set environment variable")
    // })

    t.Run("no updates available", func(t *testing.T) {
        mockExec := &mockExecutor{
            stdout: []string{"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."},
            errors: []error{nil},
        }

        updater := &Updater{
            CommandExecutor: mockExec,
            Request:         &pb.UpdateSystemSoftwareRequest{},
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return false, 0, nil
			},
		}

        proceedWithReboot, err := updater.Update()
        assert.NoError(t, err)
		assert.False(t, proceedWithReboot)
        assert.Equal(t, 0, len(mockExec.commands))       
    })

    t.Run("insufficient disk space", func(t *testing.T) {
        mockExec := &mockExecutor{
            stdout: []string{"After this operation, 500 MB of additional disk space will be used."},
            errors: []error{nil},
        }

        updater := &Updater{
            CommandExecutor: mockExec,
            Request:         &pb.UpdateSystemSoftwareRequest{},
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100 * 1024, nil // Simulate insufficient disk space
			},
		}

        proceedWithReboot, err := updater.Update()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "Not enough free disk space")
		assert.False(t, proceedWithReboot)
	})

    t.Run("execute fullInstall mode", func(t *testing.T) {
        mockExec := &mockExecutor{
			stdout: []string{"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."},
            stderr: []string{""},
			errors: []error{nil},
		}
        updater := &Updater{
            CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL,
            },
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100000000, nil
			},
        }

        proceedWithReboot, err := updater.Update()
        assert.NoError(t, err)
		assert.True(t, proceedWithReboot)
        assert.Greater(t, len(mockExec.commands), 0)
    })

    t.Run("execute noDownload mode", func(t *testing.T) {
        mockExec := &mockExecutor{
			stderr: []string{""},
			stdout: []string{""},
			errors: []error{nil},
		}
        updater := &Updater{
            CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD,
            },
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100000000, nil
			},
        }

        proceedWithReboot, err := updater.Update()
        assert.NoError(t, err)
		assert.True(t, proceedWithReboot)
        assert.Greater(t, len(mockExec.commands), 0)
    })

    t.Run("execute downloadOnly mode", func(t *testing.T) {
        mockExec := &mockExecutor{
			stderr: []string{""},
			stdout: []string{""},
			errors: []error{nil},
		}
        updater := &Updater{
            CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY,
            },
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100000000, nil
			},
        }

        proceedWithReboot, err := updater.Update()
        assert.NoError(t, err)
		assert.True(t, proceedWithReboot)
        assert.Greater(t, len(mockExec.commands), 0)
    })

    t.Run("invalid mode", func(t *testing.T) {
        mockExec := &mockExecutor{}
        updater := &Updater{
            CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_UNSPECIFIED, // Invalid mode
            },
			GetEstimatedSize: func(cmdExec utils.Executor) (bool, uint64, error){
				return true, 500 * 1024, nil
			},
			GetFreeDiskSpaceInBytes: func(path string) (uint64, error) {
				return 100000000, nil
			},
        }

        proceedWithReboot, err := updater.Update()
        assert.Error(t, err)
		assert.False(t, proceedWithReboot)
        assert.Contains(t, err.Error(), "Invalid mode")
    })
}

func TestSizeToBytes(t *testing.T) {
	tests := []struct {
		name     string
		size     string
		unit     string
		expected uint64
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
			expected: uint64(1.5 * 1024 * 1024 * 1024),
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
		expectedSize := uint64(524288000)

		isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
		assert.NoError(t, err)
		assert.True(t, isUpdateAvail)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("size estimation with commas", func(t *testing.T) {
		upgradeOutput := "After this operation, 1,000 MB of additional disk space will be used."
		expectedSize := uint64(1048576000)

		isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
		assert.NoError(t, err)
		assert.True(t, isUpdateAvail)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("size estimation with different units", func(t *testing.T) {
		upgradeOutput := "After this operation, 1.5 GB of additional disk space will be used."
		expectedSize := uint64(1610612736)

		isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
		assert.NoError(t, err)
		assert.True(t, isUpdateAvail)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("no size information", func(t *testing.T) {
		upgradeOutput := "No size information available."
		expectedSize := uint64(0)

		isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get size of the update")
		assert.False(t, isUpdateAvail)
		assert.Equal(t, expectedSize, size)
	})

	t.Run("size estimation with freed space", func(t *testing.T) {
		upgradeOutput := "After this operation, 500 MB of disk space will be freed."
		expectedSize := uint64(0)

		isUpdateAvail, size, err := getEstimatedSizeInBytesFromAptGetUpgrade(upgradeOutput)
		assert.NoError(t, err)
		assert.True(t, isUpdateAvail)
		assert.Equal(t, expectedSize, size)
	})
}

