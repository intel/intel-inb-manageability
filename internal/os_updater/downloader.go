/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// Downloader is an interface that contains the method to download the update.
type Downloader interface {
	download() error
}

type downloader struct {}

// Abstract downloader method
func (d *downloader) download() error {
	return nil
}
