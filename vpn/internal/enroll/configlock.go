package enroll

import (
	"errors"
	"fmt"
)

// errConfigLockUnavailable means the lock file could not even be opened (for
// example a read-only mount). A writer must treat it as fatal; a reader may go
// on without the lock because every writer replaces the file atomically.
var errConfigLockUnavailable = errors.New("enroll: config lock unavailable")

func lockUnavailable(lockPath string, err error) error {
	return fmt.Errorf("%w: %s: %w", errConfigLockUnavailable, lockPath, err)
}

// rmwAfterLoad runs after a credential command has changed the in-memory
// config and before that config is written, while the config lock is held.
// Tests set it to widen the window between read and write. It is nil in
// production, and a nil hook is not called.
var rmwAfterLoad func()

// updateConfig holds the config lock for the whole read-modify-write.
// fn may return an error to leave the file untouched.
func updateConfig(path string, fn func(*Config) error) error {
	release, err := acquireConfigLock(path)
	if err != nil {
		return err
	}
	defer release()
	cfg, err := LoadFile(path)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	if rmwAfterLoad != nil {
		rmwAfterLoad()
	}
	return SaveFile(path, cfg)
}

// withConfigLock serializes a read of path with concurrent updates. When the
// lock file cannot be opened (a read-only mount of a backup or of a running
// deployment) the read proceeds unlocked: writers swap the file in with an
// atomic rename, so a reader sees either the old or the new document.
func withConfigLock(path string, fn func() error) error {
	release, err := acquireConfigLock(path)
	if errors.Is(err, errConfigLockUnavailable) {
		return fn()
	}
	if err != nil {
		return err
	}
	defer release()
	return fn()
}
