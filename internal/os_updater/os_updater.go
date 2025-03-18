/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// UpdateOS updates the OS depending on the OS type.
func UpdateOS(req *pb.UpdateSystemSoftwareRequest, factory UpdaterFactory) (*pb.UpdateResponse, error) {
	
	// Download the update
	downloader := factory.CreateDownloader(req.Mode)
	err := downloader.Download()
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
	}

	// Update the OS
	updater := factory.CreateUpdater()
	err = updater.Update()
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
	}

	// Reboot the system
	rebooter := factory.CreateRebooter()
	err = rebooter.Reboot()
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
	}

	return &pb.UpdateResponse{StatusCode: 200, Error: ""}, nil
}