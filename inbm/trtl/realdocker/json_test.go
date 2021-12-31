package realdocker

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerOptionsGetsCorrectStructure(t *testing.T) {
	valid := "[{\"device\": [\"/dev/video0\", \"/dev/video1\"], \"execcmd\": \"/bin/bash -c /home/app.sh\"}]"

	expected := ContainerOptions{Device: []string{"/dev/video0", "/dev/video1"}, Execcmd: "/bin/bash -c /home/app.sh"}

	result, err := ContainerOptionsUnmarshal([]byte(valid))
	assert.Equal(t, expected, result[0])
	assert.NoError(t, err)
}

func TestContainerOptionsErrorsOnInvalidStructure(t *testing.T) {
	invalid := "[{\"device\": \"/dev/video0\", \"execcmd: \"/bin/bash -c /home/app.sh\"}]"

	_, err := ContainerOptionsUnmarshal([]byte(invalid))
	assert.Error(t, err)
}

func TestContainerLogOptionsGetsCorrectStructure(t *testing.T) {
	valid := "[{\"details\": \"true\", \"since\": \"5m\", \"tail\": \"4\"}]"

	expected := ContainerLogOptions{Details: "true", Since: "5m", Tail: "4"}

	result, err := ContainerLogOptionsUnmarshal([]byte(valid))
	assert.Equal(t, expected, result[0])
	assert.NoError(t, err)
}

func TestContainerLogOptionsWithOptionsMissing(t *testing.T) {
	valid := "[{\"since\": \"5m\", \"tail\": \"4\"}]"

	expected := ContainerLogOptions{Since: "5m", Tail: "4"}

	result, err := ContainerLogOptionsUnmarshal([]byte(valid))
	assert.Equal(t, expected, result[0])
	assert.NoError(t, err)
}

func TestContainerLogOptionsErrorsOnInvalidStructure(t *testing.T) {
	invalid := "[{\"details\":, \"since\": \"5m\", \"tail\": \"4\"}]"

	_, err := ContainerLogOptionsUnmarshal([]byte(invalid))
	assert.Error(t, err)
}
