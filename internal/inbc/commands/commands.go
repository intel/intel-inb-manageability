/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package commands are the commands that are used by the INBC tool.
package commands

var (
// Common flags
)

// Panic on error, because the error is known statically never to occur. If it
// does, then a programming error occurred, not a user or runtime error, such
// as a race condition.
//
// This helper exists for when the Go type system is not sufficiently strong or
// not sufficiently used.
//
// In the case of Cobra, it is useful when checking the return of
// MarkFlagRequired-type function. The function should only error if there is a
// typo in the code or the flag is created out of order.
func must(err error) {
	if err != nil {
		panic("PROGRAMMING ERROR: " + err.Error())
	}
}
