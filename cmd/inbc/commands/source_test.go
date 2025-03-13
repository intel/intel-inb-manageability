/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */
 
// Package commands are the commands that are used by the INBC tool.
package commands

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestSourceCmd(t *testing.T) {
    cmd := SourceCmd()

    assert.Equal(t, "source", cmd.Use, "command use should be 'source'")
    assert.Equal(t, "Modifies the source files for Updates", cmd.Short, "command short description should match")
    assert.Equal(t, "Source command is used to modify the application and OS files used for performing updates.", cmd.Long, "command long description should match")

    subcommands := cmd.Commands()
    assert.Len(t, subcommands, 2, "there should be 2 subcommands")

    applicationCmd := subcommands[0]
    assert.Equal(t, "application", applicationCmd.Use, "first subcommand should be 'application'")

    osCmd := subcommands[1]
    assert.Equal(t, "os", osCmd.Use, "second subcommand should be 'os'")
}

func TestSourceApplicationSubCmd(t *testing.T) {
    cmd := SourceApplicationCmd()
    assert.NotNil(t, cmd, "SourceApplicationCmd should not be nil")
    assert.Equal(t, "application", cmd.Use, "command use should be 'application'")
}

func TestSourceOSSubCmd(t *testing.T) {
    cmd := SourceOSCmd()
    assert.NotNil(t, cmd, "SourceOSCmd should not be nil")
    assert.Equal(t, "os", cmd.Use, "command use should be 'os'")
}