//go:build windows

package main

// Windows has no Unix owner. The copy under %ProgramFiles%\iDoris is protected
// by the ACL applied when the task is installed, not by a uid.
func requireRoot() error               { return nil }
func chownSystemRootImpl(string) error { return nil }
