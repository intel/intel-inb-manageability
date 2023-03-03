/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/
package realdocker

import (
	"fmt"
	"io"

	"github.com/docker/docker/api/types"
)

// Events calls the docker events api and waits to receive messages.
// It returns any error encountered.
func Events(dw DockerWrapper) error {

	message, errs := dw.Events(types.EventsOptions{})
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
