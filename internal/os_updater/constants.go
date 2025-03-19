/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

const (
	// DockerChrootPrefix is a prefix to run a command 'as the host' using docker, chroot, and namespace control.
	// Note this will not propagate proxy environment variables
	// change above comment if -e entries are added for proxies
	DockerChrootPrefix = "/usr/bin/docker run -e DEBIAN_FRONTEND=noninteractive --privileged --rm --net=host --pid=host -v /:/host ubuntu:20.04 /usr/sbin/chroot /host "
)
