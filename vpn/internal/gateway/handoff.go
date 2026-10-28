package gateway

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PlanHandoff is what `sudo idoris-vpnd gateway apply` knows about the plan
// file the unprivileged wizard wrote. The directory does not have to be
// owned by root.
type PlanHandoff struct {
	Symlink     bool
	Regular     bool
	Mode        os.FileMode
	UID         int
	DirWritable bool
	Root        bool
	SudoUID     string
}

// CheckPlanHandoff accepts a regular file that is not a symlink, mode no
// wider than 0600, in a directory that is not group- or other-writable.
// The owner must be root, or the SUDO_UID value when this process is root.
// SUDO_UID is ignored for any other process.
func CheckPlanHandoff(h PlanHandoff) error {
	if h.Symlink {
		return errors.New("gateway: plan file is a symlink")
	}
	if !h.Regular {
		return errors.New("gateway: plan file is not a regular file")
	}
	if h.Mode.Perm()&^0o600 != 0 {
		return fmt.Errorf("gateway: plan file mode %o is wider than 0600", h.Mode.Perm())
	}
	if h.DirWritable {
		return errors.New("gateway: plan directory is writable by group or others")
	}
	if h.UID == 0 {
		return nil
	}
	if h.Root {
		if id, ok := parseSudoUID(h.SudoUID); ok && id == h.UID {
			return nil
		}
	}
	return fmt.Errorf("gateway: plan file is owned by uid %d", h.UID)
}

func parseSudoUID(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return 0, false
	}
	id, err := strconv.Atoi(raw)
	if err != nil || id < 0 {
		return 0, false
	}
	return id, true
}
