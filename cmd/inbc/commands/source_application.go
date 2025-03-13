/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */
 
// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"github.com/spf13/cobra"
)

// SourceApplicationCmd returns a cobra command for the Source Application command
func SourceApplicationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "application",
		Short: "Modifies the source files for Application Updates",
		Long:  `Source command is used to modify the application files used for performing application updates.`,
	}

	// Add subcommands to Source Application command
	cmd.AddCommand(AddApplicationSourceCmd())
	cmd.AddCommand(RemoveApplicationSourceCmd())

	return cmd
}
