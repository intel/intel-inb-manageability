package realdocker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: This is technically an integration test because it calls Instantiate
func TestDockerSnapshot(t *testing.T) {
	df := DockerFinder{}
	dw := DockerWrap{}

	s, err := NewInstance(0, "hello-world", nil).Snapshot(df, dw)
	assert.NoError(t, err)

	s2, err := s.Snapshot(df, dw)
	assert.NoError(t, err)
	assert.Equal(t, "hello-world", s2.GetName())
	assert.Equal(t, 2, s2.GetVersion())
}
