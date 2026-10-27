package vpnd

import "path/filepath"

func dirOf(path string) string {
	return filepath.Dir(path)
}
