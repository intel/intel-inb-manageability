/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package inbd

import (
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
)

// ServerDeps groups the dependencies needed for running the server.
type ServerDeps struct {
	Socket          string
	Stat            func(string) (os.FileInfo, error)
	Remove          func(string) error
	NetListen       func(network, address string) (net.Listener, error)
	Umask           func(int) int
	NewGRPCServer   func(...grpc.ServerOption) *grpc.Server
	RegisterService func(*grpc.Server)
	ServeFunc       func(*grpc.Server, net.Listener) error
}

// RunServer implements the core logic of the server:
// • If a socket file already exists then remove it.
// • Adjust the process umask (saving and then restoring the previous value)
// • Create a UNIX domain listener on Socket.
// • Create a new gRPC server, register the inbd service and then serve.
func RunServer(deps ServerDeps) error {
	// If the socket file exists, try to remove before binding.
	if _, err := deps.Stat(deps.Socket); err == nil {
		if err := deps.Remove(deps.Socket); err != nil {
			return fmt.Errorf("error removing socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("unexpected stat error: %w", err)
	}

	// Set the umask to 0177 (so that the created socket has 0600 permissions)
	// and then restore the previous value afterward.
	oldUmask := deps.Umask(0177)
	lis, err := deps.NetListen("unix", deps.Socket)
	deps.Umask(oldUmask)
	if err != nil {
		return fmt.Errorf("error listening on socket: %w", err)
	}

	grpcServer := deps.NewGRPCServer()
	deps.RegisterService(grpcServer)

	return deps.ServeFunc(grpcServer, lis)
}
