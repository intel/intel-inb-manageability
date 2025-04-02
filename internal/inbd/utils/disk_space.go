/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package utils provides utility functions.
package utils

import (
    "fmt"
    "golang.org/x/sys/unix"
)

// GetFreeDiskSpaceInBytes returns the amount of free disk space in bytes for the given path.
// It uses the unix.Statfs function to retrieve filesystem statistics.
func GetFreeDiskSpaceInBytes(path string) (uint64, error) {
    var stat unix.Statfs_t

    // Get filesystem statistics for the given path
    err := unix.Statfs(path, &stat)
    if err != nil {
        return 0, fmt.Errorf("failed to get filesystem stats: %w", err)
    }	

    // Calculate free space in bytes
    freeSpace := stat.Bavail * uint64(stat.Bsize)
    return freeSpace, nil
}