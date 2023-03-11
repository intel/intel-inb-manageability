/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"github.com/spf13/afero"
	"os"
)

// OpenFile opens a file handle
// returns file handle or any error
func OpenFile(fileName string, appFs afero.Fs) (afero.File, error) {
	f, err := appFs.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open the file: %s", err)
		return nil, err
	}

	return f, nil
}

// CloseFile synchronizes an open file handle and then closes the handle.
// Nothing is returned, since this is called in a defer statement.
func CloseFile(fh afero.File) {
	if err := fh.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sync file: %s", err)
	}

	if err := fh.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close file handle: %s", err)
	}
}
