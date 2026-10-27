//go:build !windows

package main

func protectWindowsPath(string, bool) error { return nil }

func protectWindowsInstall(string, string, string, string, []string) error { return nil }
