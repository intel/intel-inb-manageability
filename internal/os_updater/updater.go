/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: LicenseRef-Intel
 */

// Package osupdater updates the OS.
package osupdater

// IUpdater is an interface that contains the method to update the OS.
type IUpdater interface {
	update() error
}

type updater struct {}

// Abstract update method
func (u *updater) update() error {
	return nil
}
