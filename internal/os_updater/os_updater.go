/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"log"
	"os/exec"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	emt "github.com/intel/intel-inb-manageability/internal/os_updater/emt"
)

// UpdateOS updates the OS depending on the OS type.
func UpdateOS(req *pb.UpdateSystemSoftwareRequest, factory UpdaterFactory) (*pb.UpdateResponse, error) {
	// Create a cleaner to remove the artifacts later.
	cleaner := emt.NewCleaner(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput))

	log.Printf("Request Mode: %v\n", req.Mode)

	if req.Mode != pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_NO_DOWNLOAD {
		// Download the update
		downloader := factory.CreateDownloader(req)
		err := downloader.Download()
		if err != nil {
			return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
		}
	}

	// Update the OS
	updater := factory.CreateUpdater(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), req)
	proceedWithReboot, err := updater.Update()
	if err != nil {
		// Remove the artifacts if failure happens.
		// TODO:  This is only done for EMT, but it's also being done for Ubuntu.
		// Need way to only do this for EMT.
		errDel := cleaner.DeleteAll(emt.DownloadDir + "/")
		if errDel != nil {
			log.Printf("[Warning] %v", errDel.Error())
		}
		return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
	}

	log.Println("Update completed successfully.")
      
  // Remove the artifacts after update success.
	err = cleaner.DeleteAll(emt.DownloadDir + "/")
	if err != nil {
		log.Printf("[Warning] %v", err.Error())
	}
      
	if proceedWithReboot {
		if req.Mode != pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_DOWNLOAD_ONLY {
			// Reboot the system
			rebooter := factory.CreateRebooter(utils.NewExecutor(exec.Command, utils.ExecuteAndReadOutput), req)
			err = rebooter.Reboot()
			if err != nil {
				return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
			}
		}
	}

	return &pb.UpdateResponse{StatusCode: 200, Error: ""}, nil
}
