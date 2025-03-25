package osupdater

import (
	"io"
	"strings"

	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// Configurations represents the structure of the XML configuration file
type Configurations struct {
	TrustedRepositories []string `yaml:"trustedRepositories"`
}

// LoadConfig loads the XML configuration file
func LoadConfig(fs afero.Fs, filename string) (*Configurations, error) {
	file, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config Configurations
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// IsTrustedRepository checks if the given URL is in the list of trusted repositories
func IsTrustedRepository(url string, config *Configurations) bool {
	for _, repo := range config.TrustedRepositories {
		if strings.HasPrefix(url, repo) {
			return true
		}
	}
	return false
}
