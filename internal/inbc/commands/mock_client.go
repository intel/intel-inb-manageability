/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"context"
	"fmt"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// MockInbServiceClient is a mock implementation of the pb.InbServiceClient interface.
type MockInbServiceClient struct {
	mock.Mock
}

// AddApplicationSource is a mock implementation of the AddApplicationSource function.
func (m *MockInbServiceClient) AddApplicationSource(ctx context.Context, req *pb.AddApplicationSourceRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*pb.UpdateResponse), args.Error(1)
}

// RemoveApplicationSource is a mock implementation of the RemoveApplicationSource function.
func (m *MockInbServiceClient) RemoveApplicationSource(ctx context.Context, req *pb.RemoveApplicationSourceRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*pb.UpdateResponse), args.Error(1)
}

// UpdateOSSource is a mock implementation of the UpdateOSSource function.
func (m *MockInbServiceClient) UpdateOSSource(ctx context.Context, req *pb.UpdateOSSourceRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*pb.UpdateResponse), args.Error(1)
}

// UpdateSystemSoftware is a mock implementation of the UpdateSystemSoftware function.
func (m *MockInbServiceClient) UpdateSystemSoftware(ctx context.Context, req *pb.UpdateSystemSoftwareRequest, opts ...grpc.CallOption) (*pb.UpdateResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*pb.UpdateResponse), args.Error(1)
}

// MockClientConn is a mock implementation of the grpc.ClientConnInterface interface.
type MockClientConn struct {
	grpc.ClientConnInterface
}

// Close is a mock implementation of the Close function.
func (m *MockClientConn) Close() error {
	return nil
}

// MockDialer is a mock implementation of the Dialer function
func MockDialer(_ context.Context, _ string, client *MockInbServiceClient, shouldError bool) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
	if shouldError {
		return nil, nil, fmt.Errorf("mock dialer error")
	}

	return client, &MockClientConn{}, nil
}
