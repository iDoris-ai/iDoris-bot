//go:build windows

package vpnd

import "os"

// platformStatusFileOwner cannot confirm an owner on Windows. Callers refuse
// to delete a status path when ok is false.
func platformStatusFileOwner(os.FileInfo) (int, bool) { return 0, false }
