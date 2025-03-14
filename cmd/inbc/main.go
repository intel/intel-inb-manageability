/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/intel/intel-inb-manageability/internal/inbc/commands"
)

// Version is set with linker flags at build time.
var Version string

func main() {
	// Root command and persistent flags
	rootCmd := &cobra.Command{
		Use:     "inbc",
		Short:   "INBC - CLI for Intel Manageability",
		Version: Version,
		Long:    `INBC is a CLI to access and perform manageability commands.`,
	}
	verbose := rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")

	// Add subcommands
	rootCmd.AddCommand(commands.SOTACmd(), commands.SourceCmd())

	// Execute CLI
	if err := rootCmd.Execute(); err != nil {
		if *verbose {
			fmt.Println(err)
		}
		os.Exit(1)
	}
}
