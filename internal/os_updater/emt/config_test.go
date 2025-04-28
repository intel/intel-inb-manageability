/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

import (
    "testing"

    "github.com/spf13/afero"
    "github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
    t.Run("successful load", func(t *testing.T) {
        fs := afero.NewMemMapFs()
        configContent := `
        {
            "os_updater": {
                "trustedRepositories": ["https://example.com/repo1", "https://example.com/repo2"]
            }
        }`

        err := afero.WriteFile(fs, "config.json", []byte(configContent), 0644)
        assert.NoError(t, err)

        config, err := LoadConfig(fs, "config.json")
        assert.NoError(t, err)
        assert.NotNil(t, config)
        assert.Equal(t, 2, len(config.OSUpdater.TrustedRepositories))
        assert.Equal(t, "https://example.com/repo1", config.OSUpdater.TrustedRepositories[0])
        assert.Equal(t, "https://example.com/repo2", config.OSUpdater.TrustedRepositories[1])
    })

    t.Run("file not found", func(t *testing.T) {
        fs := afero.NewMemMapFs()

        config, err := LoadConfig(fs, "nonexistent.json")
        assert.Error(t, err)
        assert.Nil(t, config)
    })

    t.Run("invalid JSON", func(t *testing.T) {
        fs := afero.NewMemMapFs()
        configContent := `
        {
            "os_updater": {
                "trustedRepositories": ["https://example.com/repo1", "https://example.com/repo2
            }
        }`
        err := afero.WriteFile(fs, "config.json", []byte(configContent), 0644)
        assert.NoError(t, err)

        config, err := LoadConfig(fs, "config.json")
        assert.Error(t, err)
        assert.Nil(t, config)
    })
}

func TestIsTrustedRepository(t *testing.T) {
    config := &Configurations{ 
        OSUpdater: struct {
            TrustedRepositories []string `json:"trustedRepositories"`
        }{
            TrustedRepositories: []string{
                "https://example.com/repo1", 
                "https://example.com/repo2"},
        },
    }

    t.Run("trusted repository", func(t *testing.T) {
        url := "https://example.com/repo1/some/path"
        result := IsTrustedRepository(url, config)
        assert.True(t, result)
    })

    t.Run("untrusted repository", func(t *testing.T) {
        url := "https://untrusted.com/repo"
        result := IsTrustedRepository(url, config)
        assert.False(t, result)
    })

    t.Run("empty URL", func(t *testing.T) {
        url := ""
        result := IsTrustedRepository(url, config)
        assert.False(t, result)
    })
}
