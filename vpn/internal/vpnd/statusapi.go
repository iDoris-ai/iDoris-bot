package vpnd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EmbeddedNoPathWarning is added to the status warnings when an embedded
// member has neither a loopback forward nor a SOCKS5 listener. Other
// applications on the machine then have no path into the tailnet.
const EmbeddedNoPathWarning = "embedded mode does not install tailnet routes for other applications on this machine; add forwards or socks5_listen, or switch to system mode"

// StatusSource is anything that can report a Snapshot (the Reconciler).
type StatusSource interface {
	Snapshot() Snapshot
}

// View is the status API's source. It overlays the process-wide mode and the
// loopback listeners onto the reconciler snapshot. The reconciler does not
// know which mode it was started in, and its own set() would otherwise drop
// fields it does not own.
type View struct {
	Source     StatusSource
	Mode       string
	ModeReason string
	Access     *LocalAccess
}

// Snapshot implements StatusSource.
func (v View) Snapshot() Snapshot {
	var snap Snapshot
	if v.Source != nil {
		snap = v.Source.Snapshot()
	}
	snap.Mode = v.Mode
	snap.ModeReason = v.ModeReason
	if v.Access != nil {
		snap.Forwards = v.Access.ForwardStatus()
		snap.SOCKS5 = v.Access.SOCKS5Status()
	}
	if embeddedMemberWithoutPath(snap) {
		snap.Warnings = appendWarning(snap.Warnings, EmbeddedNoPathWarning)
	}
	return snap
}

func embeddedMemberWithoutPath(snap Snapshot) bool {
	if snap.Mode != ModeEmbedded {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(snap.Role))
	if role != "" && role != "member" {
		return false
	}
	if len(snap.Forwards) > 0 {
		return false
	}
	if snap.SOCKS5 != nil && strings.TrimSpace(snap.SOCKS5.Listen) != "" {
		return false
	}
	return true
}

func appendWarning(in []string, extra string) []string {
	for _, w := range in {
		if w == extra {
			out := make([]string, len(in))
			copy(out, in)
			return out
		}
	}
	out := make([]string, 0, len(in)+1)
	out = append(out, in...)
	return append(out, extra)
}

// StatusSwap lets the status server publish a snapshot before the reconciler
// exists (waiting for tailscaled) and then switch to the live view.
type StatusSwap struct {
	mu  sync.RWMutex
	src StatusSource
}

// Store replaces the source. Snapshot copies through whatever is current.
func (s *StatusSwap) Store(src StatusSource) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.src = src
	s.mu.Unlock()
}

// Snapshot implements StatusSource.
func (s *StatusSwap) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{Phase: PhaseUnknown}
	}
	s.mu.RLock()
	src := s.src
	s.mu.RUnlock()
	if src == nil {
		return Snapshot{Phase: PhaseUnknown}
	}
	return src.Snapshot()
}

type staticSnapshot struct{ snap Snapshot }

func (s staticSnapshot) Snapshot() Snapshot { return s.snap }

// FixedSnapshot is a StatusSource that always returns s.
func FixedSnapshot(s Snapshot) StatusSource { return staticSnapshot{snap: s} }

// FormatStatus renders /v1/status for `idoris-vpnd status`.
func FormatStatus(st map[string]any) string {
	var b strings.Builder
	line := func(key string, val any) {
		fmt.Fprintf(&b, "%-13s %v\n", key+":", val)
	}
	line("phase", st["phase"])
	if st["mode"] != nil && st["mode"] != "" {
		line("mode", st["mode"])
	}
	if reason, _ := st["mode_reason"].(string); reason != "" {
		line("mode_reason", reason)
	}
	line("control_url", st["control_url"])
	line("backend", st["backend_state"])
	if ips, ok := st["tailnet_ips"].([]any); ok && len(ips) > 0 {
		line("tailnet_ips", ips)
	}
	if v, _ := st["self_dns_name"].(string); v != "" {
		line("self", v)
	}
	if fw, ok := st["forwards"].([]any); ok {
		for _, item := range fw {
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			fmt.Fprintf(&b, "%-13s %v -> %v (%v)", "forward:", m["listen"], m["target"], m["state"])
			if errText, _ := m["error"].(string); errText != "" {
				fmt.Fprintf(&b, " error=%s", errText)
			}
			fmt.Fprintln(&b)
		}
	}
	if s5, ok := st["socks5"].(map[string]any); ok && s5["listen"] != "" {
		fmt.Fprintf(&b, "%-13s %v (%v)", "socks5:", s5["listen"], s5["state"])
		if errText, _ := s5["error"].(string); errText != "" {
			fmt.Fprintf(&b, " error=%s", errText)
		}
		if auth, _ := s5["auth_file"].(string); auth != "" {
			fmt.Fprintf(&b, " auth=%s", auth)
		}
		fmt.Fprintln(&b)
	}
	if routes, ok := st["routes"].([]any); ok {
		for _, item := range routes {
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			mark := "pending"
			if m["approved"] == true {
				mark = "approved"
			}
			fmt.Fprintf(&b, "%-13s %v (%s)\n", "route:", m["cidr"], mark)
		}
	}
	if v, _ := st["admin_hint"].(string); v != "" {
		line("admin_hint", v)
	}
	if v, _ := st["role"].(string); v != "" {
		line("role", v)
	}
	if reachable, ok := st["enroll_reachable"].(bool); ok && !reachable {
		line("enroll", "unreachable")
	}
	if warnings, ok := st["warnings"].([]any); ok {
		for _, w := range warnings {
			fmt.Fprintf(&b, "%-13s %v\n", "warning:", w)
		}
	}
	if v, _ := st["last_error"].(string); v != "" {
		line("last_error", v)
	}
	line("attempts", st["login_attempts"])
	line("daemon", st["daemon_version"])
	return b.String()
}

// StatusHandler serves /healthz and /v1/status for the Bridge Connector and
// for `idoris-vpnd status`.
func StatusHandler(src StatusSource, version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		s := src.Snapshot()
		w.Header().Set("Content-Type", "text/plain")
		if s.Phase == PhaseConnected {
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "%s\n", s.Phase)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Snapshot
			Version string `json:"daemon_version"`
		}{src.Snapshot(), version})
	})
	return mux
}

// ParseListen accepts "unix:/path/to.sock" or "tcp:127.0.0.1:7845".
func ParseListen(s string) (network, address string, err error) {
	switch {
	case strings.HasPrefix(s, "unix:"):
		return "unix", strings.TrimPrefix(s, "unix:"), nil
	case strings.HasPrefix(s, "tcp:"):
		addr := strings.TrimPrefix(s, "tcp:")
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "", "", fmt.Errorf("listen %q: %w", s, err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return "", "", fmt.Errorf("listen %q: tcp status API must bind a loopback address", s)
		}
		return "tcp", addr, nil
	default:
		return "", "", fmt.Errorf("listen %q: expected unix:<path> or tcp:<loopback:port>", s)
	}
}

// Listen opens the status listener. Unix sockets are created 0600 and any
// stale socket file is removed first.
func Listen(spec string) (net.Listener, error) {
	network, addr, err := ParseListen(spec)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.MkdirAll(filepath.Dir(addr), 0o700); err != nil {
			return nil, err
		}
		if _, err := os.Stat(addr); err == nil {
			// Refuse to steal a live socket from another daemon instance.
			c, derr := net.DialTimeout("unix", addr, 500*time.Millisecond)
			if derr == nil {
				_ = c.Close()
				return nil, fmt.Errorf("another idoris-vpnd is already serving %s", addr)
			}
			_ = os.Remove(addr)
		}
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(addr, 0o600); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

// ServeStatus runs the HTTP server until ctx is done.
func ServeStatus(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type statusDial struct {
	network string
	addr    string
}

type statusDialKey struct{}

// statusClient is shared by every QueryStatus call. Keep-alives are off
// because the URL host is constant while the dial address comes from the
// request: a cached connection would be for the wrong socket. The dial
// address is stored on the request context.
var statusClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			spec, ok := ctx.Value(statusDialKey{}).(statusDial)
			if !ok || spec.network == "" || spec.addr == "" {
				return nil, errors.New("vpnd: status query has no dial address")
			}
			var d net.Dialer
			return d.DialContext(ctx, spec.network, spec.addr)
		},
	},
}

// QueryStatus fetches /v1/status from a running daemon at listen spec.
func QueryStatus(ctx context.Context, spec string) (map[string]any, error) {
	network, addr, err := ParseListen(spec)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, statusDialKey{}, statusDial{network: network, addr: addr})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://idoris-vpnd/v1/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := statusClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
