/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

// Updater is an interface that contains the method to update the OS.
type Updater interface {
	Update() (bool, error)
}
