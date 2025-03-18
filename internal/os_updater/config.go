package os_updater

import (
    "gopkg.in/yaml.v3"
    "fmt"
    "os"
    "strings"
)

// Configurations represents the structure of the XML configuration file
type Configurations struct {
    TrustedRepositories []string `yaml:"trustedRepositories"`
}

// LoadConfig loads the XML configuration file
func LoadConfig(filename string) (*Configurations, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    content, err := os.Readfile(filename)
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

