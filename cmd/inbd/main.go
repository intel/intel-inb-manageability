/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"syscall"

	"google.golang.org/grpc"

	"github.com/intel/intel-inb-manageability/internal/inbd"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

func main() {
	socket := flag.String("s", "/var/run/inbd.sock", "UNIX domain socket path")
	flag.Parse()

	// Build our dependency struct using real functions.
	deps := inbd.ServerDeps{
		Socket:        *socket,
		Stat:          os.Stat,
		Remove:        os.Remove,
		NetListen:     net.Listen,
		Umask:         syscall.Umask,
		NewGRPCServer: grpc.NewServer,
		RegisterService: func(gs *grpc.Server) {
			// Register our inbdServer implementation.
			pb.RegisterInbServiceServer(gs, &inbd.InbdServer{})
		},
		ServeFunc: func(gs *grpc.Server, lis net.Listener) error {
			log.Printf("Server listening on %s", *socket)
			return gs.Serve(lis)
		},
	}

	// Run the server (returning an error instead of calling log.Fatal internally).
	if err := inbd.RunServer(deps); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
