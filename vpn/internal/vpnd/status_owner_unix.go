//go:build unix

package vpnd

import (
	"os"
	"syscall"
)

func platformStatusFileOwner(info os.FileInfo) (int, bool) {
	if info == nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return int(st.Uid), true
}
