/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"iotg-inb/trtl/dockercompose"
	"iotg-inb/trtl/util"
)

// ComposerInfo is a struct that contains Composer specific instance information
type ComposerInfo struct{}

var down = dockercompose.Down
var downWithFile = dockercompose.DownWithFile
var up = dockercompose.Up
var upWithFile = dockercompose.UpWithFile
var pull = dockercompose.Pull
var pullWithFile = dockercompose.PullWithFile

// Down will call Docker Compose Down command with a default yaml file
func (composer *ComposerInfo) Down(instanceName string) {
	if err := down(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Down will call Docker Compose Down command with a designated yaml file
func (composer *ComposerInfo) DownWithFile(instanceName string, fileName string) {
	if err := downWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}

// Up will call Docker Compose Up command without a YML file.
func (composer *ComposerInfo) Up(instanceName string) {
	if err := up(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// UpWithFile will call Docker Compose Up command with the specified YML file
func (composer *ComposerInfo) UpWithFile(instanceName string, fileName string) {
	if err := upWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}

// Pull pulls the latest changes of all images mentioned in the file
func (composer *ComposerInfo) Pull(instanceName string) {
	if err := pull(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Pull pulls the latest changes of all images mentioned in the file
func (composer *ComposerInfo) PullWithFile(instanceName string, fileName string) {
	if err := pullWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}
