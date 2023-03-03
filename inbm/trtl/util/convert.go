/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"os"
	"strconv"
)

var osExit = os.Exit

// ConvertToInt converts a string to an integer.
func ConvertToInt(x string) int {
	y, err := strconv.Atoi(x)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting string '%s' to integer: %s", x, err)
		osExit(1)
	}
	return y
}
