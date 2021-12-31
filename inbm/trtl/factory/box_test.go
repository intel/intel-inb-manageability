package factory

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

// unit test
func TestFactoryCreatesDockerInfoType(t *testing.T) {
	box, err := CreateBox("docker")

	assert.Equal(t, reflect.TypeOf(new(DockerInfo)), reflect.TypeOf(box))
	assert.NoError(t, err)
}

func TestFactoryCreatesBtrfsInfoType(t *testing.T) {
	box, err := CreateBox("btrfs")
	assert.Equal(t, reflect.TypeOf(new(SnapperInfo)), reflect.TypeOf(box))
	assert.NoError(t, err)
}

func TestFactoryCreatesComposeInfoType(t *testing.T) {
	box, err := CreateBox("compose")
	assert.Equal(t, reflect.TypeOf(new(ComposeInfo)), reflect.TypeOf(box))
	assert.NoError(t, err)
}

func TestReturnErrorOnInvalidContainerType(t *testing.T) {
	_, err := CreateBox("qbert")
	assert.Error(t, err, "Invalid Box Type")
}
