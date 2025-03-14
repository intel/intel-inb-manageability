/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */

// Package osupdater updates the OS.
package osupdater

// IDownloader is an interface that contains the method to download the update.
type IDownloader interface {
	download() error
}

type downloader struct {}

// Abstract downloader method
func (d *downloader) download() error {
	return nil
}
