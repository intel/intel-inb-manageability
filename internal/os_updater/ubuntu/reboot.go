/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package ubuntu updates the Ubuntu OS.
package ubuntu

import (
	"fmt"
	"log"
	"time"

	"github.com/intel/intel-inb-manageability/internal/inbd/utils"
	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

// Rebooter is the concrete implementation of the Updater interface
// for the Ubuntu OS.
type Rebooter struct {
	CommandExecutor utils.Executor
	Request         *pb.UpdateSystemSoftwareRequest
}

// Reboot method for Ubuntu
func (u *Rebooter) Reboot() error {
	if u.Request.DoNotReboot {
		log.Println("Reboot is disabled.  Skipping reboot.")
		return nil
	}

	fmt.Print("Rebooting ")
	time.Sleep(2 * time.Second)

	cmd := "/sbin/reboot"

	_, _, err := u.CommandExecutor.Execute([]string{cmd})
	if err != nil {
		return fmt.Errorf("SOTA Aborted: Reboot Failed: %s", err)
	}

	return nil
}
