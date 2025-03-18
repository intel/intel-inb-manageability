/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package inbd

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"google.golang.org/grpc"
)

// dummyFileInfo implements os.FileInfo for testing.
type dummyFileInfo struct{}

func (d dummyFileInfo) Name() string       { return "dummy.sock" }
func (d dummyFileInfo) Size() int64        { return 0 }
func (d dummyFileInfo) Mode() os.FileMode  { return 0600 }
func (d dummyFileInfo) ModTime() time.Time { return time.Time{} }
func (d dummyFileInfo) IsDir() bool        { return false }
func (d dummyFileInfo) Sys() interface{}   { return nil }

// fakeListener is a dummy net.Listener.
type fakeListener struct {
	closed bool
}

func (fl *fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("fake listener: no connection")
}

func (fl *fakeListener) Close() error {
	fl.closed = true
	return nil
}

func (fl *fakeListener) Addr() net.Addr {
	return fakeAddr("fakeAddr")
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

// TestRunServer_Success verifies that when no socket file exists RunServer succeeds.
func TestRunServer_Success(t *testing.T) {
	fl := &fakeListener{}
	removeCalled := false

	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			// Simulate file not exists.
			return nil, os.ErrNotExist
		},
		Remove: func(name string) error {
			removeCalled = true
			return nil
		},
		NetListen: func(network, address string) (net.Listener, error) {
			if network != "unix" || address != "dummy.sock" {
				return nil, errors.New("unexpected parameters")
			}
			return fl, nil
		},
		Umask: func(mask int) int {
			// Return 0 for the old umask.
			return 0
		},
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {
			// Registration indicator.
		},
		ServeFunc: func(gs *grpc.Server, lis net.Listener) error {
			if lis != fl {
				return errors.New("listener mismatch")
			}
			// No actual serving.
			return nil
		},
	}

	err := RunServer(deps)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if removeCalled {
		t.Errorf("Remove should not be called because Stat returned os.ErrNotExist")
	}
}

// TestRunServer_RemoveError simulates a failure removing the existing socket.
func TestRunServer_RemoveError(t *testing.T) {
	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			return dummyFileInfo{}, nil
		},
		Remove: func(name string) error {
			return errors.New("remove failed")
		},
		// Other functions are not invoked.
		NetListen: nil,
		Umask:     syscall.Umask,
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {},
		ServeFunc:       func(gs *grpc.Server, lis net.Listener) error { return nil },
	}
	err := RunServer(deps)
	if err == nil || err.Error() != "error removing socket: remove failed" {
		t.Errorf("Expected error on remove, got %v", err)
	}
}

// TestRunServer_NetListenError simulates a failure when creating the listener.
func TestRunServer_NetListenError(t *testing.T) {
	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		Remove: os.Remove,
		NetListen: func(network, address string) (net.Listener, error) {
			return nil, errors.New("netListen failed")
		},
		Umask: func(mask int) int { return 0 },
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {},
		ServeFunc:       func(gs *grpc.Server, lis net.Listener) error { return nil },
	}
	err := RunServer(deps)
	if err == nil || err.Error() != "error listening on socket: netListen failed" {
		t.Errorf("Expected netListen error, got %v", err)
	}
}

// TestRunServer_ServeError simulates an error during serving.
func TestRunServer_ServeError(t *testing.T) {
	fl := &fakeListener{}
	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		Remove: os.Remove,
		NetListen: func(network, address string) (net.Listener, error) {
			return fl, nil
		},
		Umask: func(mask int) int { return 0 },
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {},
		ServeFunc: func(gs *grpc.Server, lis net.Listener) error {
			return errors.New("serve error")
		},
	}
	err := RunServer(deps)
	if err == nil || err.Error() != "serve error" {
		t.Errorf("Expected serve error, got %v", err)
	}
}

// TestRunServer_RegisterCalled verifies that RegisterService is invoked.
func TestRunServer_RegisterCalled(t *testing.T) {
	registerCalled := false
	fl := &fakeListener{}

	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		Remove: os.Remove,
		NetListen: func(network, address string) (net.Listener, error) {
			return fl, nil
		},
		Umask: func(mask int) int { return 0 },
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {
			registerCalled = true
		},
		ServeFunc: func(gs *grpc.Server, lis net.Listener) error {
			return nil
		},
	}

	err := RunServer(deps)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !registerCalled {
		t.Errorf("Expected RegisterService to be called")
	}
}

// TestRunServer_UmaskRestoration verifies that Umask is called to set and then restore.
func TestRunServer_UmaskRestoration(t *testing.T) {
	var maskSet []int
	fl := &fakeListener{}

	deps := ServerDeps{
		Socket: "dummy.sock",
		Stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		Remove: os.Remove,
		NetListen: func(network, address string) (net.Listener, error) {
			return fl, nil
		},
		Umask: func(mask int) int {
			maskSet = append(maskSet, mask)
			return 0 // old umask
		},
		NewGRPCServer: func(opts ...grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(opts...)
		},
		RegisterService: func(gs *grpc.Server) {},
		ServeFunc:       func(gs *grpc.Server, lis net.Listener) error { return nil },
	}
	err := RunServer(deps)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(maskSet) != 2 {
		t.Errorf("Expected Umask to be called twice, got %d", len(maskSet))
	}
	if maskSet[0] != 0177 {
		t.Errorf("Expected first Umask call with 0177, got %o", maskSet[0])
	}
	if maskSet[1] != 0 {
		t.Errorf("Expected second Umask call with 0, got %o", maskSet[1])
	}
}

// ----------------------------------------------------------------------------
// Tests for InbdServer methods
// ----------------------------------------------------------------------------

func TestInbdServer_UpdateOSSource(t *testing.T) {
	srv := &InbdServer{}
	resp, err := srv.UpdateOSSource(context.Background(), &pb.UpdateOSSourceRequest{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode != 501 || resp.Error != "Not implemented" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}

func TestInbdServer_AddApplicationSource(t *testing.T) {
	srv := &InbdServer{}
	resp, err := srv.AddApplicationSource(context.Background(), &pb.AddApplicationSourceRequest{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode != 501 || resp.Error != "Not implemented" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}

func TestInbdServer_RemoveApplicationSource(t *testing.T) {
	srv := &InbdServer{}
	resp, err := srv.RemoveApplicationSource(context.Background(), &pb.RemoveApplicationSourceRequest{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode != 501 || resp.Error != "Not implemented" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}
