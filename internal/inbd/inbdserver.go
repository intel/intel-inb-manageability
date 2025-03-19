/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

package inbd

import (
	"context"
	"github.com/intel/intel-inb-manageability/internal/logger"
	osUpdater "github.com/intel/intel-inb-manageability/internal/os_updater"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

type InbdServer struct {
	pb.UnimplementedInbServiceServer
}

// UpdateSystemSoftware updates the system software
func (s *InbdServer) UpdateSystemSoftware(ctx context.Context, req *pb.UpdateSystemSoftwareRequest) (*pb.UpdateResponse, error) {
	logger.Debug("Received UpdateSystemSoftware request")
	os, err := osUpdater.DetectOS()
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 415, Error: err.Error()}, nil
	}

	sotaFactory, err := osUpdater.GetOSUpdaterFactory(os)
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 415, Error: err.Error()}, nil
	}

	resp, err := osUpdater.UpdateOS(req, sotaFactory)
	if err != nil {
		return &pb.UpdateResponse{StatusCode: 500, Error: err.Error()}, nil
	}
	
	return &pb.UpdateResponse{StatusCode: resp.StatusCode, Error: resp.Error}, nil
}

// UpdateOSSource creates a new /etc/apt/sources.list file with only the sources provided
func (s *InbdServer) UpdateOSSource(ctx context.Context, req *pb.UpdateOSSourceRequest) (*pb.UpdateResponse, error) {
	logger.Debug("Received UpdateOSSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}

// AddApplicationSource adds a new source to the /etc/apt/sources.list.d/ directory
func (s *InbdServer) AddApplicationSource(ctx context.Context, req *pb.AddApplicationSourceRequest) (*pb.UpdateResponse, error) {
	logger.Debug("Received AddApplicationSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}

// RemoveApplicationSource removes a source from the /etc/apt/sources.list.d/ directory
func (s *InbdServer) RemoveApplicationSource(ctx context.Context, req *pb.RemoveApplicationSourceRequest) (*pb.UpdateResponse, error) {
	logger.Debug("Received RemoveApplicationSource request")
	return &pb.UpdateResponse{StatusCode: 501, Error: "Not implemented"}, nil
}
