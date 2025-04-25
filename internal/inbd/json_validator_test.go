package inbd

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestIsValidJSON(t *testing.T) {
	schemaContent := `{
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Intel Manageability Configuration Schema",
        "type": "object",
        "properties": {
            "os_updater": {
                "type": "object",
                "properties": {
                    "trustedRepositories": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "format": "uri"
                        },
                        "description": "A list of trusted repository URLs."
                    }
                },
                "required": ["trustedRepositories"],
                "additionalProperties": false
            }
        },
        "required": ["os_updater"],
        "additionalProperties": false
    }`
	tests := []struct {
		name           string
		schemaContent  string
		jsonContent    string
		expectedResult bool
		expectedError  error
	}{
		{
			name:          "valid JSON against schema",
			schemaContent: schemaContent,
			jsonContent: `{
                    "os_updater": {
                        "trustedRepositories": ["https://example.com/repo1", "https://example.com/repo2"]
                    }
                }`,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name:          "invalid JSON against schema",
			schemaContent: schemaContent,
			jsonContent: `{
                    "fw_updater": {
                        "trustedRepositories": ["https://example.com/repo1", "https://example.com/repo2"]
                    }
                }`,
			expectedResult: false,
			expectedError:  errors.New("JSON file is invalid: Field: (root) - Issue: os_updater is required; Field: (root) - Issue: Additional property fw_updater is not allowed; "),
		},
		{
			name:           "error reading JSON file",
			schemaContent:  schemaContent,
			jsonContent:    "",
			expectedResult: false,
			expectedError:  errors.New("failed to read JSON file: open /jsonFile.json: file does not exist"),
		},
		{
			name:           "error reading schema file",
			schemaContent:  "",
			jsonContent:    `{"os_updater": {"trustedRepositories": ["https://example.com/repo1"]}}`,
			expectedResult: false,
			expectedError:  errors.New("failed to read schema file: open /schema.json: file does not exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock filesystem
			fs := afero.NewMemMapFs()

			// Write the schema file to the mock filesystem
			schemaFilePath := "/schema.json"
            if tt.schemaContent != "" {
                err := afero.WriteFile(fs, schemaFilePath, []byte(tt.schemaContent), 0644)
                assert.NoError(t, err)
            }
			// Write the JSON file to the mock filesystem (if content is provided)
			jsonFilePath := "/jsonFile.json"
			if tt.jsonContent != "" {
				err := afero.WriteFile(fs, jsonFilePath, []byte(tt.jsonContent), 0644)
				assert.NoError(t, err)
			}

			// Call the function under test
			result, err := IsValidJSON(afero.Afero{Fs: fs}, schemaFilePath, jsonFilePath)

			// Assert the result
			assert.Equal(t, tt.expectedResult, result)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
