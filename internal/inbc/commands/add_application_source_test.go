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

func TestAddApplicationSourceCmd(t *testing.T) {
	cmd := AddApplicationSourceCmd()

	assert.Equal(t, "add", cmd.Use, "command use should be 'add'")
	assert.Equal(t, "Adds a new application source", cmd.Short, "command short description should match")
	assert.Equal(t, `Add command is used to add a new application source to the list of sources.`, cmd.Long, "command long description should match")

	flags := cmd.Flags()

	socket, err := flags.GetString("socket")
	assert.NoError(t, err)
	assert.Equal(t, "/var/run/inbd.sock", socket, "default socket should be '/var/run/inbd.sock'")

	sources, err := flags.GetStringSlice("sources")
	assert.NoError(t, err)
	assert.Empty(t, sources, "default sources should be an empty slice")

	filename, err := flags.GetString("filename")
	assert.NoError(t, err)
	assert.Equal(t, "", filename, "default filename should be empty")

	gpgKeyURI, err := flags.GetString("gpg-key-uri")
	assert.NoError(t, err)
	assert.Equal(t, "", gpgKeyURI, "default gpg-key-uri should be empty")

	gpgKeyName, err := flags.GetString("gpg-key-name")
	assert.NoError(t, err)
	assert.Equal(t, "", gpgKeyName, "default gpg-key-name should be empty")
}

func TestHandleAddApplicationSource(t *testing.T) {
	socket := "/var/run/inbd.sock"
	filename := "testfile"
	sources := []string{"source1", "source2"}
	gpgKeyURI := "http://example.com/key"
	gpgKeyName := "testkey"
	cmd := &cobra.Command{}
	args := []string{}

	t.Run("successful add application source", func(t *testing.T) {
		mockClient := new(MockInbServiceClient)
		mockClient.On("AddApplicationSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{
			StatusCode: 200,
			Error:      "",
		}, nil)

		dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
			return MockDialer(ctx, socket, mockClient, false)
		}

		err := handleAddApplicationSource(&socket, &sources, &filename, &gpgKeyURI, &gpgKeyName, dialer)(cmd, args)
		assert.NoError(t, err, "handleAddApplicationSource should not return an error")

		mockClient.AssertExpectations(t)
	})

	t.Run("duplicate source in sources list", func(t *testing.T) {
		dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
			return MockDialer(ctx, socket, new(MockInbServiceClient), false)
		}

		sameSources := []string{"source1", "source1"}

		err := handleAddApplicationSource(&socket, &sameSources, &filename, &gpgKeyURI, &gpgKeyName, dialer)(cmd, args)
		assert.Error(t, err, "duplicate source in the sources list: source1")
	})

	t.Run("gRPC client setup error", func(t *testing.T) {
		dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
			return MockDialer(ctx, socket, new(MockInbServiceClient), true)
		}

		err := handleAddApplicationSource(&socket, &sources, &filename, &gpgKeyURI, &gpgKeyName, dialer)(cmd, args)
		assert.Error(t, err, "error setting up new gRPC client")
	})

	t.Run("gRPC AddApplicationSource error", func(t *testing.T) {
		mockClient := new(MockInbServiceClient)
		mockClient.On("AddApplicationSource", mock.Anything, mock.Anything, mock.Anything).Return(&pb.UpdateResponse{}, errors.New("error adding application source"))

		dialer := func(ctx context.Context, socket string) (pb.InbServiceClient, grpc.ClientConnInterface, error) {
			return MockDialer(ctx, socket, mockClient, false)
		}

		err := handleAddApplicationSource(&socket, &sources, &filename, &gpgKeyURI, &gpgKeyName, dialer)(cmd, args)
		assert.Error(t, err, "error adding application source")
	})
}
