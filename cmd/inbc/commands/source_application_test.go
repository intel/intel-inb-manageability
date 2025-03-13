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

func TestSourceApplicationCmd(t *testing.T) {
    cmd := SourceApplicationCmd()

    assert.Equal(t, "application", cmd.Use, "command use should be 'application'")
    assert.Equal(t, "Modifies the source files for Application Updates", cmd.Short, "command short description should match")
    assert.Equal(t, `Source command is used to modify the application files used for performing application updates.`, cmd.Long, "command long description should match")

    subcommands := cmd.Commands()
    assert.Len(t, subcommands, 2, "there should be 2 subcommands")

    addCmd := subcommands[0]
    assert.Equal(t, "add", addCmd.Use, "first subcommand should be 'add'")

    removeCmd := subcommands[1]
    assert.Equal(t, "remove", removeCmd.Use, "second subcommand should be 'remove'")
}

func TestAddApplicationSourceSubCmd(t *testing.T) {
    cmd := AddApplicationSourceCmd()
    assert.NotNil(t, cmd, "AddApplicationSourceCmd should not be nil")
    assert.Equal(t, "add", cmd.Use, "command use should be 'add'")
}

func TestRemoveApplicationSourceSubCmd(t *testing.T) {
    cmd := RemoveApplicationSourceCmd()
    assert.NotNil(t, cmd, "RemoveApplicationSourceCmd should not be nil")
    assert.Equal(t, "remove", cmd.Use, "command use should be 'remove'")
}
