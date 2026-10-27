package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
)

// osHost is the real machine. Tests use a fake that implements the same methods.
type osHost struct{}

func (osHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func (osHost) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func (osHost) Stat(path string) (os.FileInfo, error)        { return os.Stat(path) }
func (osHost) Chmod(path string, mode os.FileMode) error    { return os.Chmod(path, mode) }
func (osHost) ReadFile(path string) ([]byte, error)         { return os.ReadFile(path) }
func (osHost) IsRoot() bool                                 { return os.Geteuid() == 0 }
func (osHost) GOOS() string                                 { return runtime.GOOS }

// EnableIPForward writes the sysctl drop-in and applies it. If forwarding is
// already on, a failing sysctl (some container runtimes mark the knob
// read-only) is still success.
func (osHost) EnableIPForward(path, content string) error {
	if runtime.GOOS != "linux" {
		return errors.New("ip_forward is only supported on Linux")
	}
	// sysctl.d is a system directory (0755) and drop-ins are mode 0644. The file contains no secret.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // system directory
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // sysctl drop-in, no secret
		return err
	}
	already := false
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) == "1" {
		already = true
	}
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil && !already {
		return fmt.Errorf("sysctl ip_forward: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osHost) InstallService(configPath string) error { return installService(configPath) }

// fileHost is gateway.Host plus the reads the wizard needs.
type fileHost interface {
	gateway.Host
	ReadFile(path string) ([]byte, error)
}
