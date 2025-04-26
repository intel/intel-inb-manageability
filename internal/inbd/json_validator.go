/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package inbd provides the main functionality for the Intel Manageability Daemon (IMD).
package inbd

import (
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/xeipuuv/gojsonschema"
)

// IsValidJSON validates the JSON configuration file against the JSON schema.
func IsValidJSON(fs afero.Afero, schemaFilePath string, jsonFilePath string) (bool, error) {
	// Read the schema file
    schemaContent, err := fs.ReadFile(schemaFilePath)
    if err != nil {
        return false, fmt.Errorf("failed to read schema file: %w", err)
    }
 
    // Read the JSON file
    jsonContent, err := fs.ReadFile(jsonFilePath)
    if err != nil {
        return false, fmt.Errorf("failed to read JSON file: %w", err)
    }
 
    // Use a canonical URI for the schema
    schemaLoader := gojsonschema.NewStringLoader(string(schemaContent))
    jsonLoader := gojsonschema.NewStringLoader(string(jsonContent))

    // Validate the JSON against the schema
    result, err := gojsonschema.Validate(schemaLoader, jsonLoader)
    if err != nil {
        return false, fmt.Errorf("failed to validate JSON file: %w", err)
    }

    if !result.Valid() {
        var errorDetails strings.Builder
        for _, desc := range result.Errors() {
            errorDetails.WriteString(fmt.Sprintf("Field: %s - Issue: %s; ",
                desc.Field(), desc.Description()))
        }
        return false, fmt.Errorf("JSON file is invalid: %s", errorDetails.String())
    }

    return true, nil
}
