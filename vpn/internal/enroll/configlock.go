package enroll

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

// withConfigLock serializes a read of path with concurrent updates.
func withConfigLock(path string, fn func() error) error {
	release, err := acquireConfigLock(path)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}
