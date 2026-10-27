//go:build !windows

package main

// protectWindowsPath lives in service_acl_windows.go. This file only
// supplies the install entry point so non-Windows builds still link.
func protectWindowsInstall(string, string, string, string, []string) error { return nil }
