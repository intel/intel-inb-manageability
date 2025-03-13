/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */
 
// Package commands are the commands that are used by the INBC tool.
package commands

import (
    "context"
    "errors"
    "testing"

    pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "google.golang.org/grpc"
)

func TestUpdateOSSourceCmd(t *testing.T) {
    cmd := UpdateOSSourceCmd()

    assert.Equal(t, "update", cmd.Use, "command use should be 'update'")
    assert.Equal(t, "Creates a new /etc/apt/sources.list file", cmd.Short, "command short description should match")
    assert.Equal(t, "Update command is used to creates a new /etc/apt/sources.list file with only the sources provided.", cmd.Long, "command long description should match")

    flags := cmd.Flags()

    socket, err := flags.GetString("socket")
    assert.NoError(t, err)
    assert.Equal(t, "/var/run/inbd.sock", socket, "default socket should be '/var/run/inbd.sock'")

    sources, err := flags.GetStringSlice("sources")
    assert.NoError(t, err)
    assert.Empty(t, sources, "default sources should be an empty slice")
}

func TestHandleUpdateOSSource(t *testing.T) {
    socket := "/var/run/inbd.sock"
    sources := []string{"source1", "source2"}
    cmd := &cobra.Command{}
    args := []string{}

    t.Run("successful update OS source", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("UpdateOSSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{
            StatusCode: 200,
            Error:      "",
        }, nil)

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleUpdateOSSource(&socket, &sources, dialer)(cmd, args)
        assert.NoError(t, err, "handleUpdateOSSource should not return an error")

        mockClient.AssertExpectations(t)
    })

    t.Run("duplicate source in sources list", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        sameSources := []string{"source1", "source1"}

        err := handleUpdateOSSource(&socket, &sameSources, dialer)(cmd, args)
        assert.Error(t, err, "duplicate source in the sources list: source1")
    })

    t.Run("gRPC client setup error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, true)
        }

        err := handleUpdateOSSource(&socket, &sources, dialer)(cmd, args)
        assert.Error(t, err, "error setting up new gRPC client")
    })

    t.Run("gRPC UpdateOSSource error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("UpdateOSSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{}, errors.New("error updating OS sources"))

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleUpdateOSSource(&socket, &sources, dialer)(cmd, args)
        assert.Error(t, err, "error updating OS sources")
    })
}
