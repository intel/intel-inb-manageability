package osupdater

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockFileHandler struct {
	StatFunc     func(name string) (os.FileInfo, error)
	CreateFunc   func(name string) (FileWriter, error)
	OpenFileFunc func(name string, flag int, perm os.FileMode) (FileWriter, error)
}

func (m *MockFileHandler) Stat(name string) (os.FileInfo, error) {
	return m.StatFunc(name)
}

func (m *MockFileHandler) Create(name string) (FileWriter, error) {
	return m.CreateFunc(name)
}

func (m *MockFileHandler) OpenFile(name string, flag int, perm os.FileMode) (FileWriter, error) {
	return m.OpenFileFunc(name, flag, perm)
}

type MockJSONHandler struct {
	MarshalIndentFunc func(v interface{}, prefix, indent string) ([]byte, error)
}

func (m MockJSONHandler) MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return m.MarshalIndentFunc(v, prefix, indent)
}

type MockFile struct {
	WriteFunc func([]byte) (int, error)
	CloseFunc func() error
}

func (m *MockFile) Write(p []byte) (int, error) {
	return m.WriteFunc(p)
}

func (m *MockFile) Close() error {
	return m.CloseFunc()
}

func TestWriteUpdateStatus_Success(t *testing.T) {

	mockFile := &MockFile{
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockHandler := &MockFileHandler{
		StatFunc: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		CreateFunc: func(name string) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
		OpenFileFunc: func(name string, flag int, perm os.FileMode) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
	}

	mockJSONHandler := MockJSONHandler{
		MarshalIndentFunc: func(v interface{}, prefix, indent string) ([]byte, error) {
			return json.MarshalIndent(v, prefix, indent)
		},
	}

	err := writeUpdateStatusWithHandler(mockHandler, mockJSONHandler, "Success", "Metadata", "")
	assert.NoError(t, err)
}

func TestWriteUpdateStatus_FileOpenError(t *testing.T) {

	mockFile := &MockFile{
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockHandler := &MockFileHandler{
		StatFunc: func(name string) (os.FileInfo, error) {
			return nil, nil
		},
		CreateFunc: func(name string) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
		OpenFileFunc: func(name string, flag int, perm os.FileMode) (FileWriter, error) {
			return nil, errors.New("failed to open file")
		},
	}

	mockJSONHandler := MockJSONHandler{
		MarshalIndentFunc: func(v interface{}, prefix, indent string) ([]byte, error) {
			return json.MarshalIndent(v, prefix, indent)
		},
	}

	err := writeUpdateStatusWithHandler(mockHandler, mockJSONHandler, "Failure", "Metadata", "Error")
	assert.Error(t, err)
	assert.Equal(t, "failed to open file", err.Error())
}

func TestWriteUpdateStatus_FileCreateError(t *testing.T) {

	mockFile := &MockFile{
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockHandler := &MockFileHandler{
		StatFunc: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		CreateFunc: func(name string) (FileWriter, error) {
			return nil, errors.New("failed to create file")
		},
		OpenFileFunc: func(name string, flag int, perm os.FileMode) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
	}

	mockJSONHandler := MockJSONHandler{
		MarshalIndentFunc: func(v interface{}, prefix, indent string) ([]byte, error) {
			return json.MarshalIndent(v, prefix, indent)
		},
	}

	err := writeUpdateStatusWithHandler(mockHandler, mockJSONHandler, "Failure", "Metadata", "Error")
	assert.Error(t, err)
	assert.Equal(t, "failed to create file", err.Error())
}

func TestWriteUpdateStatus_JSONMarshalError(t *testing.T) {

	mockFile := &MockFile{
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockHandler := &MockFileHandler{
		StatFunc: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		CreateFunc: func(name string) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
		OpenFileFunc: func(name string, flag int, perm os.FileMode) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
	}

	mockJSONHandler := MockJSONHandler{
		MarshalIndentFunc: func(v interface{}, prefix, indent string) ([]byte, error) {
			return nil, errors.New("JSON marshal error")
		},
	}

	err := writeUpdateStatusWithHandler(mockHandler, mockJSONHandler, "Failure", "Metadata", "Error")
	assert.Error(t, err)
	assert.Equal(t, "JSON marshal error", err.Error())
}

func TestWriteUpdateStatus_FileWriteError(t *testing.T) {

	mockFile := &MockFile{
		WriteFunc: func(p []byte) (int, error) {
			return 0, errors.New("failed to write file")
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockHandler := &MockFileHandler{
		StatFunc: func(name string) (os.FileInfo, error) {
			return nil, nil
		},
		CreateFunc: func(name string) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
		OpenFileFunc: func(name string, flag int, perm os.FileMode) (FileWriter, error) {
			return (FileWriter)(mockFile), nil
		},
	}

	mockJSONHandler := MockJSONHandler{
		MarshalIndentFunc: func(v interface{}, prefix, indent string) ([]byte, error) {
			return []byte(`{"Status":"Success"}`), nil
		},
	}

	err := writeUpdateStatusWithHandler(mockHandler, mockJSONHandler, "Failure", "Metadata", "Error")
	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())
}
