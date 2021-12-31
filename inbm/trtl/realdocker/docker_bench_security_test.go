package realdocker

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDBSRunsSuccessfully(t *testing.T) {
	d := FakeDockerWrapper{
		Err: nil,
	}

	err := DockerBenchSecurity(d)
	assert.NoError(t, err)
}
