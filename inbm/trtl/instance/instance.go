/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

// Package instance provides an interface for what is needed to create an instance.
package instance

// Instance represents a given (generic) snapshot
type Instance interface {
	Snapshot() (Instance, error)
	Rollback(old Instance) error
	Exec([]string)
	GetVersion() int
	GetName() string
}
