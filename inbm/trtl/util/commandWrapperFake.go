/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/
package util

// FakeCommandExec is a structure used to set outgoing parameters of fake methods for the CommandWrapper interface.
type FakeCommandExec struct {
	Err    error
	Output []byte
}

// Run is a fake method for unit testing.
func (f FakeCommandExec) Run(command string, directory string, args []string, chrootHost bool) error {
	return f.Err
}

// CombinedOutput makes an actual call to exec.Command to run the command and get the output.
func (f FakeCommandExec) CombinedOutput(command string, directory string, args []string, chrootHost bool) ([]byte, error) {
	return f.Output, f.Err
}
