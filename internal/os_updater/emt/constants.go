/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package emt provides the implementation for updating the EMT OS.
package emt

const (
	// FAIL is a possible value for the update status.
	FAIL = "FAIL"
	// SUCCESS is a possible value for the update status.
	SUCCESS = "SUCCESS"
)

// Failure reasons for granular log
const (
	FAILURE_REASON_UNSPECIFIED          = "unspecified"
	FAILURE_REASON_DOWNLOAD             = "download"
	FAILURE_REASON_INSUFFICIENT_STORAGE = "insufficientstorage"
	FAILURE_REASON_RS_AUTHENTICATION    = "rsauthentication"
	FAILURE_REASON_SIGNATURE_CHECK      = "signaturecheck"
	FAILURE_REASON_UT_WRITE             = "utwrite"
	FAILURE_REASON_BOOT_CONFIGURATION   = "utbootconfiguration"
	FAILURE_REASON_BOOTLOADER           = "bootloader"
	FAILURE_REASON_CRITICAL_SERVICES    = "criticalservices"
	FAILURE_REASON_INBM                 = "inbm"
	FAILURE_REASON_OS_COMMIT            = "oscommit"
)