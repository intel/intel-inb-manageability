package realdocker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAllContainerUsageJSONString(t *testing.T) {

	expected := "{\"containers\":[{\"name\":\"linus\",\"cpuPercent\":0.0456},{\"name\":\"lucy\",\"cpuPercent\":0.5687}]}"

	containers := make([]ContainerUsage, 0)
	containers = append(containers, createContainerUsage("linus", 0.0456))
	containers = append(containers, createContainerUsage("lucy", 0.5687))

	result, err := createAllContainerUsageJSON(containers)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestStatsAllContainersSuccessfully(t *testing.T) {
	f := FakeFinder{
		IsFound: true,
		Err:     nil,
	}

	d := FakeDockerWrapper{
		Err: nil,
	}
	i := NewInstance(1, "abcd", nil)
	err := i.Stats(f, d, true)
	assert.NoError(t, err)
}
