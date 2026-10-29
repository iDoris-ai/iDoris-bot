//go:build windows

package vpnd

import "log/slog"

func checkSecretFile(path string) error {
	slog.Default().Warn("secret file permissions were not verified on Windows; keep the file owner-only (chmod 600)", "path", path)
	return nil
}
