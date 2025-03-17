package os_updater

import (
    "encoding/xml"
    "fmt"
    "os"
    "strings"
)

// Configurations represents the structure of the XML configuration file
type Configurations struct {
    XMLName            xml.Name `xml:"configurations"`
    TrustedRepositories []string `xml:"trustedRepositories"`
}

// LoadConfig loads the XML configuration file
func LoadConfig(filename string) (*Configurations, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    content, err := os.Readfile(file)
    if err != nil {
        return nil, err
    }

    var config Configurations
    err = xml.Unmarshal(content, &config)
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

