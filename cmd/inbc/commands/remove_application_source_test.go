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

func TestRemoveApplicationSourceCmd(t *testing.T) {
    cmd := RemoveApplicationSourceCmd()

    assert.Equal(t, "remove", cmd.Use, "command use should be 'remove'")
    assert.Equal(t, "Removes the application source file", cmd.Short, "command short description should match")
    assert.Equal(t, `Remove command is used to remove the source file from under /etc/apt/sources.list.d/.`, cmd.Long, "command long description should match")

    flags := cmd.Flags()

    socket, err := flags.GetString("socket")
    assert.NoError(t, err)
    assert.Equal(t, "/var/run/inbd.sock", socket, "default socket should be '/var/run/inbd.sock'")

    filename, err := flags.GetString("filename")
    assert.NoError(t, err)
    assert.Equal(t, "", filename, "default filename should be empty")

    gpgKeyName, err := flags.GetString("gpg-key-name")
    assert.NoError(t, err)
    assert.Equal(t, "", gpgKeyName, "default gpg-key-name should be empty")
}

func TestHandleRemoveApplicationSource(t *testing.T) {
    socket := "/var/run/inbd.sock"
    filename := "testfile"
    gpgKeyName := "testkey"
    cmd := &cobra.Command{}
    args := []string{}

    t.Run("successful remove application source", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("RemoveApplicationSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{
            StatusCode: 200,
            Error:      "",
        }, nil)

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleRemoveApplicationSource(&socket, &filename, &gpgKeyName, dialer)(cmd, args)
        assert.NoError(t, err, "handleRemoveApplicationSource should not return an error")

        mockClient.AssertExpectations(t)
    })

    t.Run("gRPC client setup error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, true)
        }

        err := handleRemoveApplicationSource(&socket, &filename, &gpgKeyName, dialer)(cmd, args)
        assert.Error(t, err, "error setting up new gRPC client")
    })

    t.Run("gRPC RemoveApplicationSource error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("RemoveApplicationSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{}, errors.New("error removing application source"))

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleRemoveApplicationSource(&socket, &filename, &gpgKeyName, dialer)(cmd, args)
        assert.Error(t, err, "error removing application source")
    })
}