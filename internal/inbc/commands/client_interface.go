/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */

// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"context"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"google.golang.org/grpc"
)

// ClientInterface is an interface for the client package
type ClientInterface interface {
	AddApplicationSource(context.Context, *pb.AddApplicationSourceRequest, ...grpc.CallOption) (*pb.UpdateResponse, error)
	RemoveApplicationSource(context.Context, pb.RemoveApplicationSourceRequest, ...grpc.CallOption) (*pb.UpdateResponse, error)
	UpdateOSSource(context.Context, pb.UpdateOSSourceRequest, ...grpc.CallOption) (*pb.UpdateResponse, error)
	UpdateSystemSoftware(context.Context, pb.UpdateSystemSoftwareRequest, ...grpc.CallOption) (*pb.UpdateResponse, error)
}

// RealClient wraps the client package calls.
type RealClient struct{
	client pb.InbServiceClient
}

// AddApplicationSource is a mock implementation of the AddApplicationSource function.
func (c *RealClient) AddApplicationSource(ctx context.Context, req *pb.AddApplicationSourceRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	return c.client.AddApplicationSource(ctx, req, opts...)
}

// RemoveApplicationSource is a mock implementation of the RemoveApplicationSource function.
func (c *RealClient) RemoveApplicationSource(ctx context.Context, req *pb.RemoveApplicationSourceRequest, opts_ ...grpc.CallOption) (*pb.UpdateResponse, error) {
	return c.client.RemoveApplicationSource(ctx, req, opts_...)
}

// UpdateOSSource is a mock implementation of the UpdateOSSource function.
func (c *RealClient) UpdateOSSource(ctx context.Context, req *pb.UpdateOSSourceRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	return c.client.UpdateOSSource(ctx, req, opts...)
}

// UpdateSystemSoftware is a mock implementation of the UpdateSystemSoftware function.
func (c *RealClient) UpdateSystemSoftware(ctx context.Context, req *pb.UpdateSystemSoftwareRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	return c.client.UpdateSystemSoftware(ctx, req, opts...)
}
