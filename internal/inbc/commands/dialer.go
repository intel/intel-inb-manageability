/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package commands are the commands that are used by the INBC tool.
package commands

import (
	"context"
	"fmt"
	"net"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Dialer is a type for dialing a gRPC client
type Dialer func(ctx context.Context, addr string) (pb.InbServiceClient, *grpc.ClientConn, error)

// Dial returns a new gRPC client
func Dial(ctx context.Context, addr string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		// cut off the unix:// part
		addr = addr[7:]
		return net.Dial("unix", addr)
	}

	conn, err := grpc.NewClient("unix://"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	return pb.NewInbServiceClient(conn), conn, nil
}
