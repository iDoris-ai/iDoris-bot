package vpnd

import "path/filepath"

func dirOf(path string) string {
	return filepath.Dir(path)
}

// canonicalizePath resolves symlinks. When the final component does not
// exist yet, the longest existing ancestor is resolved and the missing
// tail is appended, so two spellings of one directory share a lock.
func canonicalizePath(path string) string {
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	missing := []string{filepath.Base(path)}
	dir := filepath.Dir(path)
	for {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			parts := make([]string, 0, 1+len(missing))
			parts = append(parts, resolved)
			for i := len(missing) - 1; i >= 0; i-- {
				parts = append(parts, missing[i])
			}
			return filepath.Clean(filepath.Join(parts...))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return path
		}
		missing = append(missing, filepath.Base(dir))
		dir = parent
	}
}
