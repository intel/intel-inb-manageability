/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

// Package logging provides logging facilities for trtl.
package logging

// DebugLogLn should be used for developer-level logs that the end
// user will not care about; it takes the same arguments as fmt.Println
// and formats them the same way
func DebugLogLn(a ...interface{}) {
	// fmt.Println(a)
}
