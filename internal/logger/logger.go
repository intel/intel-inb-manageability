/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
 
// Package logger manages the logging for the application.
package logger

import (
	"log"
	"os"
)

const (
	// LevelDebug represents the debug log level.
	LevelDebug = iota
	// LevelInfo represents the info log level.
	LevelInfo
	// LevelWarn represents the warn log level.
	LevelWarn
	// LevelError represents the error log level.
	LevelError
)

var (
	logLevel = LevelInfo
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

// SetLogLevel sets the log level.
func SetLogLevel(level int) {
	logLevel = level
}

// Debug logs a debug message.
func Debug(v ...any) {
	if logLevel <= LevelDebug {
		logger.SetPrefix("DEBUG: ")
		logger.Println(v...)
	}
}

// Info logs an info message.
func Info(v ...any) {
	if logLevel <= LevelInfo {
		logger.SetPrefix("INFO: ")
		logger.Println(v...)
	}
}

// Warn logs a warning message.
func Warn(v ...any) {
	if logLevel <= LevelWarn {
		logger.SetPrefix("WARN: ")
		logger.Println(v...)
	}
}

// Error logs an error message.
func Error(v ...any) {
	if logLevel <= LevelError {
		logger.SetPrefix("ERROR: ")
		logger.Println(v...)
	}
}
