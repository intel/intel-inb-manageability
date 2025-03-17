/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
package osupdater

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestGetOSUpdaterFactory(t *testing.T) {
    t.Run("returns EmtUpdater for Emt OS", func(t *testing.T) {
        factory, err := GetOSUpdaterFactory("Emt")
        assert.NoError(t, err)
        assert.IsType(t, &EmtUpdater{}, factory)
    })

    t.Run("returns UbuntuUpdater for Ubuntu OS", func(t *testing.T) {
        factory, err := GetOSUpdaterFactory("Ubuntu")
        assert.NoError(t, err)
        assert.IsType(t, &UbuntuUpdater{}, factory)
    })

    t.Run("returns error for unsupported OS", func(t *testing.T) {
        factory, err := GetOSUpdaterFactory("UnsupportedOS")
        assert.Error(t, err)
        assert.Nil(t, factory)
    })
}

func TestEmtUpdater(t *testing.T) {
    emtUpdater := &EmtUpdater{}

    t.Run("createDownloader returns EmtDownloader", func(t *testing.T) {
        downloader := emtUpdater.createDownloader()
        assert.IsType(t, &EmtDownloader{}, downloader)
    })

    t.Run("createUpdater returns EmtUpdater", func(t *testing.T) {
        updater := emtUpdater.createUpdater()
        assert.IsType(t, &EmtUpdater{}, updater)
    })

    t.Run("createRebooter returns EmtRebooter", func(t *testing.T) {
        rebooter := emtUpdater.createRebooter()
        assert.IsType(t, &EmtRebooter{}, rebooter)
    })
}

func TestUbuntuUpdater(t *testing.T) {
    ubuntuUpdater := &UbuntuUpdater{}

    t.Run("createDownloader returns UbuntuDownloader", func(t *testing.T) {
        downloader := ubuntuUpdater.createDownloader()
        assert.IsType(t, &UbuntuDownloader{}, downloader)
    })

    t.Run("createUpdater returns UbuntuUpdater", func(t *testing.T) {
        updater := ubuntuUpdater.createUpdater()
        assert.IsType(t, &UbuntuUpdater{}, updater)
    })

    t.Run("createRebooter returns UbuntuRebooter", func(t *testing.T) {
        rebooter := ubuntuUpdater.createRebooter()
        assert.IsType(t, &UbuntuRebooter{}, rebooter)
    })
}
