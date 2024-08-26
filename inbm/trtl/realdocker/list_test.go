package realdocker

import (
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/stretchr/testify/assert"
)

func TestListContainersSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []image.Summary{
			{ID: "abcd", RepoTags: []string{"abcd"}},
		},
	}

	err := ListContainers(d, "redis")
	assert.NoError(t, err)
}
func TestListContainersNoneImageSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []image.Summary{
			{ID: "abcd", RepoTags: []string{"<none>"}},
		},
	}

	err := ListContainers(d, "redis")
	assert.NoError(t, err)
}
