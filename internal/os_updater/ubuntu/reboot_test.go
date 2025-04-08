/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package ubuntu updates the Ubuntu OS.
package ubuntu

import (
	"errors"
	"testing"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/stretchr/testify/assert"
)

func TestUbuntuRebooter_Reboot(t *testing.T) {

    t.Run("do not reboot", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{""},
			errors: []error{nil},
		}

		rebooter := &Rebooter{
			CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                DoNotReboot: true,
            },
		}

		err := rebooter.Reboot()
		assert.NoError(t, err)
	})

	t.Run("successful reboot", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{""},
			errors: []error{nil},
		}

		rebooter := &Rebooter{
			CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                DoNotReboot: false,
            },
		}

		err := rebooter.Reboot()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/sbin/reboot"}, mockExec.commands[0])
	})

	t.Run("failed reboot", func(t *testing.T) {
		mockExec := &mockExecutor{
			stdout: []string{""},
			errors: []error{errors.New("reboot error")},
		}

		rebooter := &Rebooter{
			CommandExecutor: mockExec,
            Request: &pb.UpdateSystemSoftwareRequest{
                DoNotReboot: false,
            },
		}

		err := rebooter.Reboot()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SOTA Aborted: Reboot Failed")
		assert.Equal(t, 1, len(mockExec.commands))
		assert.Equal(t, []string{"/sbin/reboot"}, mockExec.commands[0])
	})
}
