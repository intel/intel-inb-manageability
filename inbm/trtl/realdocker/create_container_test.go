package realdocker

import (
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateContainerSuccessful(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	cmd := []string{"cmd1"}
	options := ContainerOptions{Device: []string{"/dev/video0"}, Execcmd: "/bin/bash", Port: []string{"80/tcp:80"}}
	secOptions := []string{"secOption1"}

	hostConfig := container.HostConfig{
		SecurityOpt: secOptions,
	}

	_, err := CreateContainer(d, "image", "container", cmd, options, hostConfig)
	assert.NoError(t, err)
}
