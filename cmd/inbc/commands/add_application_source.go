/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */
package commands

import (
	"context"
	"fmt"
	"log"
	"os"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/spf13/cobra"
)

// AddApplicationSourceCmd returns a cobra command for the AddApplicationSource command
func AddApplicationSourceCmd() *cobra.Command {
	var socket string
	var sources []string
	var filename string
	var gpgKeyURI string
	var gpgKeyName string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Adds a new application source",
		Long:  "Add command is used to add a new application source to the list of sources.",
		RunE:  handleAddApplicationSource(&socket, &sources, &filename, &gpgKeyURI, &gpgKeyName),
	}

	cmd.Flags().StringVar(&socket, "socket", "/var/run/inbd.sock", "UNIX domain socket path")
	cmd.Flags().StringSliceVar(&sources, "sources", nil, "List of application sources to add")
	cmd.MarkFlagRequired("sources")
	cmd.Flags().StringVar(&filename, "filename", "", "Filename of the source")
	cmd.MarkFlagRequired("filename")
	cmd.Flags().StringVar(&gpgKeyURI, "gpg-key-uri", "", "GPG key URI")
	cmd.Flags().StringVar(&gpgKeyName, "gpg-key-name", "", "GPG key name")

	return cmd
}

// handleAddApplicationSource is a helper function to handle the AddApplicationSource command
func handleAddApplicationSource(socket *string, sources *[]string, filename *string, gpgKeyURI *string, gpgKeyName *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fmt.Printf("SOURCE APPLICATION ADD INBC Command was invoked.\n")

		// Validate and parse the package list
		sourcesSet := make(map[string]struct{})
		for _, source := range *sources {
			if _, exists := sourcesSet[source]; exists {
				fmt.Println("Duplicate source in the sources list.")
				os.Exit(1)
			}
			sourcesSet[source] = struct{}{}
		}

		request := &pb.AddApplicationSourceRequest{
			Source:     *sources,
			Filename:   *filename,
			GpgKeyUri:  *gpgKeyURI,
			GpgKeyName: *gpgKeyName,
		}

		client, conn, err := Dial(context.Background(), *socket)
		if err != nil {
			log.Fatalf("Error setting up new gRPC client: %v", err)
		}
		defer conn.Close()

		resp, err := client.AddApplicationSource(context.Background(), request)
		if err != nil {
			log.Fatalf("error adding application source: %v", err)
		}

		fmt.Printf("SOURCE APPLICATION ADD Command Response: %d-%s\n", resp.GetStatusCode(), string(resp.GetError()))

		return nil
	}
}
