/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
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

func TestSOTACmd(t *testing.T) {
    cmd := SOTACmd()

    assert.Equal(t, "sota", cmd.Use, "command use should be 'sota'")
    assert.Equal(t, "Performs System Software Update", cmd.Short, "command short description should match")
    assert.Equal(t, `Updates the system software on the device.`, cmd.Long, "command long description should match")

    flags := cmd.Flags()

    socket, err := flags.GetString("socket")
    assert.NoError(t, err)
    assert.Equal(t, "/var/run/inbd.sock", socket, "default socket should be '/var/run/inbd.sock'")

    url, err := flags.GetString("uri")
    assert.NoError(t, err)
    assert.Equal(t, "", url, "default uri should be empty")

    releaseDate, err := flags.GetString("releasedate")
    assert.NoError(t, err)
    assert.Equal(t, "", releaseDate, "default release date should be empty")

    mode, err := flags.GetString("mode")
    assert.NoError(t, err)
    assert.Equal(t, "full", mode, "default mode should be 'full'")

    reboot, err := flags.GetBool("reboot")
    assert.NoError(t, err)
    assert.Equal(t, true, reboot, "default reboot should be true")

    packageList, err := flags.GetStringSlice("package-list")
    assert.NoError(t, err)
    assert.Empty(t, packageList, "default package list should be an empty slice")
}

func TestHandleSOTA(t *testing.T) {
    socket := "/var/run/inbd.sock"
    url := "http://example.com/package"
    releaseDate := "2025-03-13T00:00:00Z"
    mode := "full"
    reboot := true
    packageList := []string{"package1", "package2"}
    signature := "signature"
    cmd := &cobra.Command{}
    args := []string{}

    t.Run("successful SOTA", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("UpdateSystemSoftware", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{
            StatusCode: 200,
            Error:      "",
        }, nil)

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleSOTA(&socket, &url, &releaseDate, &mode, &reboot, &packageList, &signature, dialer)(cmd, args)
        assert.NoError(t, err, "handleSOTA should not return an error")

        mockClient.AssertExpectations(t)
    })

    t.Run("invalid release date", func(t *testing.T) {
        invalidReleaseDate := "invalid-date"
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleSOTA(&socket, &url, &invalidReleaseDate, &mode, &reboot, &packageList, &signature, dialer)(cmd, args)
        assert.Error(t, err, "error parsing release date: parsing time")
    })

    t.Run("duplicate package in package list", func(t *testing.T) {
        duplicatePackageList := []string{"package1", "package1"}
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleSOTA(&socket, &url, &releaseDate, &mode, &reboot, &duplicatePackageList, &signature, dialer)(cmd, args)
        assert.Error(t, err, "duplicate package in the package list: package1")
    })

    t.Run("invalid mode", func(t *testing.T) {
        invalidMode := "invalid-mode"
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleSOTA(&socket, &url, &releaseDate, &invalidMode, &reboot, &packageList, &signature, dialer)(cmd, args)
        assert.Error(t, err, "invalid mode. Use one of full, no-download, download-only")
    })

    t.Run("gRPC client setup error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, true)
        }

        err := handleSOTA(&socket, &url, &releaseDate, &mode, &reboot, &packageList, &signature, dialer)(cmd, args)
        assert.Error(t, err, "error setting up new gRPC client")
    })

    t.Run("gRPC UpdateSystemSoftware error", func(t *testing.T) {
        mockClient := new(MockInbServiceClient)
        mockClient.On("UpdateSystemSoftware", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{}, errors.New("error updating system software"))

        dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
            return MockDialer(ctx, socket, mockClient, false)
        }

        err := handleSOTA(&socket, &url, &releaseDate, &mode, &reboot, &packageList, &signature, dialer)(cmd, args)
        assert.Error(t, err, "error updating system software")
    })
}
