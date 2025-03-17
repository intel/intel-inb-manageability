/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// Downloader is an interface that contains the method to download the update.
type Downloader interface {
	Download() error
}

// OSDownloader is the struct to hold parameters to download the OS update
type OSDownloader struct {}

// Download is an abstract downloader method
func (d *OSDownloader) Download() error {
	return nil
}
