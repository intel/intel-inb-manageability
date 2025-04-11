/*
   Copyright (C) 2017-2025 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

// Package realdocker provides calls to the real docker API
package realdocker

import (
	"fmt"
	"io"

	"github.com/docker/docker/api/types/events"
)

// Events calls the docker events api and waits to receive messages.
// It returns any error encountered.
func Events(dw DockerWrapper) error {

	message, errs := dw.Events(events.ListOptions{})
loop:
	for {
		select {
		case err := <-errs:
			if err != nil && err != io.EOF {
				return err
			}

			break loop
		case e := <-message:
			fmt.Printf("%s\t%s\t%s\t%s\n", e.Action, e.ID, e.Type, e.From)
		}
	}
	return nil
}
