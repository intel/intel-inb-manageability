/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */
 
// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"github.com/spf13/cobra"
)

// SourceCmd returns a cobra command for the Source command
func SourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Modifies the source files for Updates",
		Long:  "Source command is used to modify the application and OS files used for performing updates.",
	}

	// Add subcommands to createCmd
	cmd.AddCommand(SourceApplicationCmd())
	cmd.AddCommand(SourceOSCmd())

	return cmd
}