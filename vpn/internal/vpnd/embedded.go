package vpnd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// stateFileName is the file tsnet.Server writes inside Dir. It is not part of
// tsnet's public API surface beyond the documented "<Dir>/tailscaled.state".
const stateFileName = "tailscaled.state"

// EmbeddedOptions configures the in-process userspace node.
type EmbeddedOptions struct {
	// StateDir is created mode 0700. It must not be the system tailscaled
	// state directory; this node has its own identity.
	StateDir string
	// Hostname is presented to the control server. Empty uses the OS hostname.
	Hostname string
	// ControlURL is the iDoris Headscale URL. Required.
	ControlURL string
	// AdvertiseTags are requested on the node. The control server decides
	// whether to grant them.
	AdvertiseTags []string
}

// Embedded is one tsnet node. Its LocalClient satisfies Backend, so the same
// Reconciler that drives system tailscaled drives this node. AuthKey is left
// empty on purpose: tsnet.Server.Start would otherwise consume a key itself,
// and a restart would race the reconciler for a second key.
//
// Observed with tailscale.com v1.104.2:
//   - No control server, empty state: Start writes ControlURL, calls
//     StartLoginInteractive because the backend is NeedsLogin, and stays there.
//     The reconciler then does CheckPrefs, Start(AuthKey, UpdatePrefs),
//     StartLoginInteractive. That Start replaces the keyless login.
//   - Restart of a never-enrolled directory is NeedsLogin again and does not
//     mint until the reconciler asks.
//   - Restart of an enrolled directory still reports NeedsLogin for a moment,
//     while tsnet itself resumes the stored node key (doLogin regen=false).
//     A Start(AuthKey) in that window cancels the resume (client.Shutdown,
//     register context canceled) and burns a pre-auth key. GetPrefs cannot
//     see the key: LocalAPI strips it. Status.HaveNodeKey stays true. The
//     reconciler waits persistedLoginSettle and only then treats a stuck
//     NeedsLogin as expiry.
type Embedded struct {
	srv      *tsnet.Server
	lc       *local.Client
	fresh    bool
	hostname string
}

// StartEmbedded creates the state directory and starts the userspace node.
// It does not log in; the caller passes Backend to the reconciler. Fresh is
// true when no state file existed before Start, which is the only time the
// reconciler should treat a Starting state as "needs a key".
func StartEmbedded(opt EmbeddedOptions, log *slog.Logger) (*Embedded, error) {
	if opt.StateDir == "" {
		return nil, errors.New("vpnd: embedded state_dir is required")
	}
	if opt.ControlURL == "" {
		return nil, errors.New("vpnd: embedded control URL is required")
	}
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(opt.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state_dir: %w", err)
	}
	if err := os.Chmod(opt.StateDir, 0o700); err != nil { //nolint:gosec // directory needs the owner execute bit; 0700 is the required mode
		return nil, fmt.Errorf("state_dir: %w", err)
	}
	host := opt.Hostname
	if host == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			host = "idoris-vpnd"
		} else {
			host = h
		}
	}
	fresh, err := stateFileMissing(opt.StateDir)
	if err != nil {
		return nil, err
	}
	srv := &tsnet.Server{
		Dir:           opt.StateDir,
		Hostname:      host,
		ControlURL:    opt.ControlURL,
		AdvertiseTags: opt.AdvertiseTags,
		UserLogf:      func(format string, args ...any) { log.Info(formatMsg(format, args...)) },
		Logf:          func(format string, args ...any) { log.Debug(formatMsg(format, args...)) },
	}
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("embedded tailscale: %w", err)
	}
	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("embedded localapi: %w", err)
	}
	log.Info("embedded tailscale started", "state_dir", opt.StateDir, "fresh", fresh, "hostname", host)
	return &Embedded{srv: srv, lc: lc, fresh: fresh, hostname: host}, nil
}

func stateFileMissing(dir string) (bool, error) {
	st, err := os.Stat(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("state_dir: %w", err)
	}
	return st.Size() == 0, nil
}

// Backend is the LocalAPI client for this node.
func (e *Embedded) Backend() Backend { return e.lc }

// Fresh reports whether the state file was absent (or empty) before Start.
func (e *Embedded) Fresh() bool { return e.fresh }

// Hostname is the name passed to tsnet and, by the daemon, to the reconciler.
func (e *Embedded) Hostname() string { return e.hostname }

// DialContext dials through the userspace stack, including MagicDNS names.
// tsnet.Server.Dial waits until the node is Running.
func (e *Embedded) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.srv.Dial(ctx, network, address)
}

// Close shuts the node down and flushes its state file.
func (e *Embedded) Close() error {
	if e == nil || e.srv == nil {
		return nil
	}
	return e.srv.Close()
}
