/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package utils provides utility functions.
package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// NewExecutor creates a new executor.
func NewExecutor[C any](createCmdFn func(name string, args ...string) *C, execCmdFn func(*C) (out []byte, e error)) Executor {
	return &executor[C]{
		createExecutableCommand: createCmdFn,
		commandExecutor:         execCmdFn,
	}
}

// Executor is an interface that contains the method to execute a command.
type Executor interface {
	Execute(args []string) ([]byte, error)
}

type executor[C any] struct {
	createExecutableCommand func(name string, args ...string) *C
	commandExecutor         func(*C) (stdout []byte, err error)
}

func (i *executor[C]) Execute(args []string) ([]byte, error) {
	executableCommand := i.createExecutableCommand(args[0], args[1:]...)
	return i.commandExecutor(executableCommand)
}

// ExecuteAndReadOutput executes a command in the operating system and returns the output.
//
// It takes an *exec.Cmd as input, executes the command, and captures both stdout and stderr.
// If the command execution fails (non-zero exit status), it returns an error containing
// the stderr output and the error message.
//
// Parameters:
//   - executableCommand: A pointer to an exec.Cmd object representing the command to execute.
//
// Returns:
//   - stdout: A byte slice containing the standard output of the command.
//   - err: An error object if the command fails, or nil if it succeeds.
func ExecuteAndReadOutput(executableCommand *exec.Cmd) (stdout []byte, err error) {
	var errbuf strings.Builder

	executableCommand.Stderr = &errbuf
	out, err := executableCommand.Output()
	fmt.Printf("'%v' output - %v", executableCommand.String(), string(out))
	if err != nil {
		return nil, fmt.Errorf("failed to run '%v' command - %v; %v", executableCommand.String(), errbuf.String(), err)
	}

	return out, nil
}

// IsSymlink checks if a file is a symlink.
func IsSymlink(filePath string) error {
	fileInfo, err := os.Lstat(filePath)

	if err != nil {
		return fmt.Errorf("lstat command failed: %v", err)
	}

	if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
		return fmt.Errorf("loading metadata failed- %v is a symlink", filePath)
	}
	return nil
}
