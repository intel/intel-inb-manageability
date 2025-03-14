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
    t.Run("returns TiberUpdater for Tiber OS", func(t *testing.T) {
        factory, err := GetOSUpdaterFactory("Tiber")
        assert.NoError(t, err)
        assert.IsType(t, &TiberUpdater{}, factory)
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

func TestTiberUpdater(t *testing.T) {
    tiberUpdater := &TiberUpdater{}

    t.Run("createDownloader returns TiberDownloader", func(t *testing.T) {
        downloader := tiberUpdater.createDownloader()
        assert.IsType(t, &TiberDownloader{}, downloader)
    })

    t.Run("createUpdater returns TiberUpdater", func(t *testing.T) {
        updater := tiberUpdater.createUpdater()
        assert.IsType(t, &TiberUpdater{}, updater)
    })

    t.Run("createRebooter returns TiberRebooter", func(t *testing.T) {
        rebooter := tiberUpdater.createRebooter()
        assert.IsType(t, &TiberRebooter{}, rebooter)
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
