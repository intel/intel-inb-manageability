package realdocker

import (
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/stretchr/testify/assert"
)

func TestFindLatestImageTag(t *testing.T) {
	image1 := image.Summary{}
	image1.RepoTags = []string{"image:1"}

	image2 := image.Summary{}
	image2.RepoTags = []string{"image:2"}
	images := []image.Summary{image1, image2}

	assert.Equal(t, 2, findLatestImage(images))
}
