package realdocker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: This is technically an integration test because it calls stop/start
func TestDockerRollback(t *testing.T) {
	df := DockerFinder{}
	dw := DockerWrap{}

	s, err := NewInstance(0, "hello-world", nil).Snapshot(df, dw)
	assert.NoError(t, err)

	_, err = s.Instantiate(ContainerOptions{}, []string{})
	assert.NoError(t, err)

	s2, err := s.Snapshot(df, dw)
	assert.NoError(t, err)

	_, err = s2.Instantiate(ContainerOptions{}, []string{})
	assert.NoError(t, err)

	_, err = s2.Start(df, dw, ContainerOptions{}, []string{})
	assert.NoError(t, err)

	err = s2.Rollback(df, dw, s)
	assert.NoError(t, err)
}
