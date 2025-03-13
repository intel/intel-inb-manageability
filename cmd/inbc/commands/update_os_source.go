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
	"google.golang.org/grpc"
)

// UpdateOSSourceCmd returns a cobra command for the Update OS Source command
func UpdateOSSourceCmd() *cobra.Command {
	var socket string
	var sources []string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Creates a new /etc/apt/sources.list file",
		Long:  "Update command is used to creates a new /etc/apt/sources.list file with only the sources provided.",
		RunE:  handleUpdateOSSource(&socket, &sources),
	}

	cmd.Flags().StringVar(&socket, "socket", "/var/run/inbd.sock", "UNIX domain socket path")
	cmd.Flags().StringSliceVar(&sources, "sources", nil, "List of sources to add")
	cmd.MarkFlagRequired("sources")

	return cmd
}

// handleUpdateOSSource is a helper function to handle the UpdateOSSource command
func handleUpdateOSSource(socket *string, sources *[]string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fmt.Printf("SOURCE OS UPDATE INBC Command was invoked.\n")

		// Validate and parse the package list
		sourcesSet := make(map[string]struct{})
		for _, source := range *sources {
			if _, exists := sourcesSet[source]; exists {
				fmt.Println("Duplicate source in the sources list.")
				os.Exit(1)
			}
			sourcesSet[source] = struct{}{}
		}

		request := &pb.UpdateOSSourceRequest{
			SourceList: *sources,
		}

		client, conn, err := Dial(context.Background(), *socket)
		if err != nil {
			log.Fatalf("Error setting up new gRPC client: %v", err)
		}
		defer func() {
			if c, ok := conn.(*grpc.ClientConn); ok {
				c.Close()
			}
		}()

		resp, err := client.UpdateOSSource(context.Background(), request)
		if err != nil {
			log.Fatalf("error updating OS sources: %v", err)
		}

		fmt.Printf("SOURCE OS UPDATE Command Response: %d-%s\n", resp.GetStatusCode(), string(resp.GetError()))

		return nil
	}
}
