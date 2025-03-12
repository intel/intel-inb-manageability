package commands

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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
	sources := []string{"source1", "source2"}
	filename := "testfile"
	gpgKeyURI := "http://example.com/key"
	gpgKeyName := "testkey"

	cmd := &cobra.Command{}
	args := []string{}

	err := handleAddApplicationSource(&socket, &sources, &filename, &gpgKeyURI, &gpgKeyName)(cmd, args)
	assert.NoError(t, err, "handleAddApplicationSource should not return an error")
}
