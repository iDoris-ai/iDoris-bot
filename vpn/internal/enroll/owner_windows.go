//go:build windows

package enroll

import "os"

func callerIDs() (uid, gid int, ok bool) { return -1, -1, false }

func refuseForeignConfig(string) error { return nil }

func preserveOwner(string, *os.File, os.FileInfo) error { return nil }
