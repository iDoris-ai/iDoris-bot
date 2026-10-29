//go:build unix

package gateway

import (
	"os"
	"path/filepath"
	"syscall"
)

// ReadPlanHandoff stats path without following a symlink. SUDO_UID is read
// from the environment and is only honoured later, when the process is root.
func ReadPlanHandoff(path string) (PlanHandoff, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return PlanHandoff{}, err
	}
	h := PlanHandoff{
		Symlink: st.Mode()&os.ModeSymlink != 0,
		Regular: st.Mode().IsRegular(),
		Mode:    st.Mode(),
		Root:    os.Geteuid() == 0,
		SudoUID: os.Getenv("SUDO_UID"),
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		h.UID = int(sys.Uid)
	}
	if h.Symlink {
		return h, nil
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return PlanHandoff{}, err
	}
	h.DirWritable = dir.Mode().Perm()&0o022 != 0
	return h, nil
}
