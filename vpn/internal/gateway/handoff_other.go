//go:build !unix

package gateway

import (
	"os"
	"path/filepath"
)

// ReadPlanHandoff stats path without following a symlink. Windows has no
// uid; a zero UID is treated as acceptable by CheckPlanHandoff only when
// the caller fills UID from somewhere else. This build reports UID 0 so a
// non-symlink regular 0600 file passes the Unix owner rule. The Windows
// secret ACL is separate.
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
