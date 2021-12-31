package util

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"testing"
)

const name = "src/c"
const nameBad = "src/d"

func setupFilesystem(t *testing.T) afero.Fs {
	appFS := afero.NewMemMapFs()
	err := appFS.MkdirAll("src/a", 0755)
	assert.NoError(t, err)
	err = afero.WriteFile(appFS, "src/a/b", []byte("file b"), 0644)
	assert.NoError(t, err)
	err = afero.WriteFile(appFS, "src/c", []byte("file c"), 0644)
	assert.NoError(t, err)
	return appFS
}

func TestOpenFileSuccessful(t *testing.T) {
	fh, err := OpenFile(name, setupFilesystem(t))
	assert.NoError(t, err)
	assert.NotNil(t, fh)
}

func TestOpenFileFails(t *testing.T) {
	fh, err := OpenFile(nameBad, setupFilesystem(t))
	assert.Error(t, err)
	assert.Nil(t, fh)
}

func TestCloseFileSuccessful(t *testing.T) {
	fh, err := OpenFile(name, setupFilesystem(t))
	assert.NoError(t, err)
	assert.NotNil(t, fh)
	CloseFile(fh)
}
