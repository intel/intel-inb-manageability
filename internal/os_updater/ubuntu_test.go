package osupdater

import (
    "errors"
    "os"
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

func TestUbuntuRebooter_Reboot(t *testing.T) {
    t.Run("successful reboot in Docker", func(t *testing.T) {
        os.Setenv("container", "docker")
        defer os.Unsetenv("container")

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
        assert.Equal(t, []string([]string{DockerChrootPrefix, "/sbin/reboot"}), mockExec.commands[0])
    })

    t.Run("successful reboot outside Docker", func(t *testing.T) {
        os.Unsetenv("container")

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

    t.Run("failed reboot in Docker", func(t *testing.T) {
        os.Setenv("container", "docker")
        defer os.Unsetenv("container")

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
        assert.Equal(t, []string([]string{DockerChrootPrefix, "/sbin/reboot"}), mockExec.commands[0])
    })

    t.Run("failed reboot outside Docker", func(t *testing.T) {
        os.Unsetenv("container")

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
