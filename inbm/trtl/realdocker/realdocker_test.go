package realdocker

import (
	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFindLatestImageTag(t *testing.T) {
	image1 := types.ImageSummary{}
	image1.RepoTags = []string{"image:1"}

	image2 := types.ImageSummary{}
	image2.RepoTags = []string{"image:2"}
	images := []types.ImageSummary{image1, image2}

	assert.Equal(t, 2, findLatestImage(images))
}
