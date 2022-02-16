/*
   Copyright (C) 2017-2022 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"os/exec"
)

// ExecCommandWrapper is an interface used for all docker commands
type ExecCommandWrapper interface {
	Run(string, string, []string, bool) error
	CombinedOutput(string, string, []string, bool) ([]byte, error)
}

// ExecCommandWrap is the structure used with the ExeCommandWrapper interface
type ExecCommandWrap struct{}

const chroot = "/usr/sbin/chroot"
const host = "/host"

// Run makes actual call to exec.Command to run the command.
// if chrootHost is true, run command in a chroot on /host
func (ec ExecCommandWrap) Run(command string, directory string, args []string, chrootHost bool) error {
	if chrootHost {
		cmd := exec.Command(chroot, append([]string{host, command}, args...)...)
		cmd.Dir = directory
		return cmd.Run()
	} else {
		cmd := exec.Command(command, args...)
		cmd.Dir = directory
		return cmd.Run()
	}
}

// CombinedOutput makes an actual call to exec.Command to run the command and get the output.
// if chrootHost is true, run command in a chroot on /host
func (ec ExecCommandWrap) CombinedOutput(command string, directory string, args []string, chrootHost bool) ([]byte, error) {
	if chrootHost {
		cmd := exec.Command(chroot, append([]string{host, command}, args...)...)
		cmd.Dir = directory
		return cmd.CombinedOutput()
	} else {
		cmd := exec.Command(command, args...)
		cmd.Dir = directory
		return cmd.CombinedOutput()
	}
}
