/*
    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/
package util

import (
	"os/exec"
)

// ExecCommandWrapper is an interface used for all docker commands
type ExecCommandWrapper interface {
	Run(string, string, []string) error
	CombinedOutput(string, string, []string) ([]byte, error)
}

// ExecCommandWrap is the structure used with the ExeCommandWrapper interface
type ExecCommandWrap struct{}

// Run makes actual call to exec.Command to run the command.
func (ec ExecCommandWrap) Run(command string, directory string, args []string) error {
	cmd := exec.Command(command, args...)
	cmd.Dir = directory
	return cmd.Run()
}

// CombinedOutput makes an actual call to exec.Command to run the command and get the output.
func (ec ExecCommandWrap) CombinedOutput(command string, directory string, args []string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Dir = directory
	return cmd.CombinedOutput()
}
