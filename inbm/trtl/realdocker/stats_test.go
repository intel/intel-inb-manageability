package realdocker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAllContainerUsageJSONString(t *testing.T) {
	expected :=  "{\"containers\":[{\"imageName\":\"docker/getting-started\",\"containerID\":\"026a7f171b69\",\"cpuPercent\":0,\"memoryUsage\":10366976,\"memoryLimit\":8232280064,\"MemoryPercent\":0.13,\"pids\":5},
	{\"imageName\":\"docker-bench-security\",\"containerID\":\"f2f94f56c5f1\",\"cpuPercent\":229.47,\"memoryUsage\":41963520,\"memoryLimit\":8232280064,\"MemoryPercent\":0.51,\"pids\":15}]}"


	containers := make([]ContainerUsage, 0)
	containers = append(containers, createContainerUsage("docker/getting-started", "026a7f171b69", "0", "10366976", "8232280064", "0.13", "5")
	containers = append(containers, createContainerUsage("docker-bench-security", "f2f94f56c5f1", "229.47", "41963520", "8232280064", "0.51", "15")

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
