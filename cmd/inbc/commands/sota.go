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
	"time"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SOTACmd returns a cobra command for the SOTA command
func SOTACmd() *cobra.Command {
	var socket string
	var url string
	var releaseDate string
	var mode string
	var reboot bool
	var packageList []string

	cmd := &cobra.Command{
		Use:   "sota",
		Short: "Performs System Software Update",
		Long:  `Updates the system software on the device.`,
		RunE:  handleSOTA(&socket, &url, &releaseDate, &mode, &reboot, &packageList),		
	}

	cmd.Flags().StringVar(&socket, "socket", "/var/run/inbd.sock", "UNIX domain socket path")
	cmd.Flags().StringVar(&url, "uri", "", "URI from which to remotely retrieve the package")
	cmd.Flags().StringVar(&releaseDate, "releasedate", "", "Release date of the new SW update (RFC3339 format)")
	cmd.MarkFlagRequired("mode")
	cmd.Flags().StringVar(&mode, "mode", "full", "Mode for installing the software update (full, no-download, download-only)")
	cmd.Flags().BoolVar(&reboot, "reboot", true, "Whether to reboot the node after the software update attempt")
	cmd.Flags().StringSliceVar(&packageList, "package-list", []string{}, "List of packages to install if whole package update isn't desired")
	
	return cmd
}

// handleSOTA is a helper function to handle the SOTA command
func handleSOTA(socket *string, url *string, releaseDate *string, mode *string, reboot *bool, packageList *[]string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fmt.Printf("SOTA INBC Command was invoked.\n")

		// Validate and parse the release date
		var releaseDateProto *timestamppb.Timestamp
		if *releaseDate != "" {
			parsedDate, err := time.Parse(time.RFC3339, *releaseDate)
			if err != nil {
				fmt.Println("Invalid release date format. Use RFC3339 format.")
				os.Exit(1)
			}
			releaseDateProto = timestamppb.New(parsedDate)
		}

		// Validate and parse the package list
		packageSet := make(map[string]struct{})
		for _, pkg := range *packageList {
			if _, exists := packageSet[pkg]; exists {
				fmt.Println("Duplicate package in the package list.")
				os.Exit(1)
			}
			packageSet[pkg] = struct{}{}
		}

		// Validate and parse the mode
		var downloadMode int32
		switch *mode {
			case "full":
				downloadMode = 0
			case "no-download":
				downloadMode = 1
			case "download-only":
				downloadMode = 2
			default:
				fmt.Println("Invalid mode. Use one of full, no-download, download-only.")
				os.Exit(1)
		}

		request := &pb.UpdateSystemSoftwareRequest{
			Url:         *url,
			ReleaseDate: releaseDateProto,
			Mode:        pb.UpdateSystemSoftwareRequest_DownloadMode(downloadMode),
			DoNotReboot: !*reboot,
			PackageList: *packageList,
		}

		client, conn, err := Dial(context.Background(), *socket)
		if err != nil {
			log.Fatalf("Error setting up new grpc client: %v", err)
		}
		defer func() {
			if c, ok := conn.(*grpc.ClientConn); ok {
				c.Close()
			}
		}()

		resp, err := client.UpdateSystemSoftware(context.Background(), request)
		if err != nil {
			log.Fatalf("error getting server version: %v", err)
		}
		
		fmt.Printf("SOTA Command Response: %d-%s\n", resp.GetStatusCode(), string(resp.GetError()))

		return nil
	}
}
