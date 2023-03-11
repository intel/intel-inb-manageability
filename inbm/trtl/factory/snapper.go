/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"
	"os"
	"iotg-inb/trtl/btrfs"
	"iotg-inb/trtl/util"
)

// SnapperInfo is a struct that contains Snapper specific instance information
type SnapperInfo struct{}

var single = btrfs.SingleSnapshot
var undo = btrfs.UndoChange
var delete = btrfs.DeleteSnapshot
var osExit = os.Exit

// SingleSnapshot will use snapper to create a single snapshot using the provided configName
// and an optional snapshot description.
func (snap *SnapperInfo) SingleSnapshot(configName string, desc string) {
	if err := single(util.ExecCommandWrap{}, configName, desc); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating single snapshot: %s", err)
		osExit(1)
	}
}

// UndoChange will undo the changes after the snapshot version using Snapper.
func (snap *SnapperInfo) UndoChange(configName string, snapshotVersion int) {
	if err := undo(util.ExecCommandWrap{}, configName, snapshotVersion); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating undoChange: %s", err)
		osExit(1)
	}
}

// List lists all snapshots on the system.
func (snap *SnapperInfo) List(instanceName string) {
	fmt.Fprint(os.Stderr, "List not supported for Snapper.")
	osExit(3)
}

// DeleteSnapshot will use Snapper to delete the specified snapshot number.
func (snap *SnapperInfo) DeleteSnapshot(configName string, snapshotNumber int) {
	if err := delete(util.ExecCommandWrap{}, configName, snapshotNumber); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating undoChange: %s", err)
		osExit(1)
	}
}
