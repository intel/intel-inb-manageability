package realdocker

import (
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
)

func TestListContainersSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd", RepoTags: []string{"abcd"}},
		},
	}

	err := ListContainers(d)
	assert.NoError(t, err)
}
func TestListContainersNoneImageSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
		Images: []types.ImageSummary{
			{ID: "abcd", RepoTags: []string{"<none>"}},
		},
	}

	err := ListContainers(d)
	assert.NoError(t, err)
}
