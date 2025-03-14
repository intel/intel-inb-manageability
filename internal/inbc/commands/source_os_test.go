/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSourceOSCmd(t *testing.T) {
	cmd := SourceOSCmd()

	assert.Equal(t, "os", cmd.Use, "command use should be 'os'")
	assert.Equal(t, "Modifies the source files for OS Updates", cmd.Short, "command short description should match")
	assert.Equal(t, "Source command is used to creates a new /etc/apt/sources.list file with only the sources provided.", cmd.Long, "command long description should match")

	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 1, "there should be 1 subcommand")

	updateCmd := subcommands[0]
	assert.Equal(t, "update", updateCmd.Use, "subcommand should be 'update'")
}

func TestUpdateOSSourceSubCmd(t *testing.T) {
	cmd := UpdateOSSourceCmd()
	assert.NotNil(t, cmd, "UpdateOSSourceCmd should not be nil")
	assert.Equal(t, "update", cmd.Use, "command use should be 'update'")
}
