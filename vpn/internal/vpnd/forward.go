package vpnd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"tailscale.com/net/socks5"
)

// Dialer is how local listeners reach a tailnet address. *net.Dialer satisfies
// it for system mode (the kernel routes tailnet IPs). The embedded node
// satisfies it with tsnet, which also resolves MagicDNS names.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ForwardStatus is one loopback forward as reported by the status API.
type ForwardStatus struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
	State  string `json:"state"`
}

// SOCKS5Status is the optional loopback SOCKS5 listener.
type SOCKS5Status struct {
	Listen string `json:"listen"`
	State  string `json:"state"`
}

// AccessOptions controls SOCKS5 authentication for StartAccess.
type AccessOptions struct {
	// SOCKS5User and SOCKS5Password are the RFC 1929 credential. Both empty
	// means "look at the auth file". Setting only one is an error.
	SOCKS5User     string
	SOCKS5Password string
	// AllowAnonymous permits a SOCKS5 listener with no authentication.
	AllowAnonymous bool
	// SOCKS5AuthFile is a 0600 file containing one "user:password" line.
	SOCKS5AuthFile string
	// StateDir, when set and SOCKS5AuthFile is empty, holds socks5.auth.
	StateDir string
}

// LocalAccess is the set of loopback forwards and the optional SOCKS5 proxy.
// It dials through Dialer and does not know whether that dialer is tsnet or
// the kernel.
type LocalAccess struct {
	dial        Dialer
	log         *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	gate        func() bool
	dialTimeout time.Duration
	user        string
	pass        string

	mu       sync.Mutex
	closed   bool
	lns      []net.Listener
	conns    map[net.Conn]struct{}
	forwards []ForwardStatus
	socks    *SOCKS5Status
	wg       sync.WaitGroup
}

// StartLocalAccess listens on each forward and on socksAddr (empty disables
// SOCKS5). Listen addresses must already have passed ValidateLoopback; a port
// of 0 selects an ephemeral port and the status reports the bound address.
// A nil dialer or a listen error fails the call and leaves nothing running.
func StartLocalAccess(dial Dialer, forwards []Forward, socksAddr string, log *slog.Logger) (*LocalAccess, error) {
	if len(forwards) == 0 && socksAddr == "" {
		return nil, nil
	}
	if dial == nil {
		return nil, errors.New("vpnd: dialer is required for forwards")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &LocalAccess{
		dial:   dial,
		log:    log,
		ctx:    ctx,
		cancel: cancel,
		conns:  map[net.Conn]struct{}{},
	}
	type pending struct {
		ln     net.Listener
		target string
		socks  bool
	}
	var pend []pending
	fail := func(err error) (*LocalAccess, error) {
		for _, p := range pend {
			_ = p.ln.Close()
		}
		cancel()
		return nil, err
	}
	for _, f := range forwards {
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			return fail(fmt.Errorf("forward %s -> %s: %w", f.Listen, f.Target, err))
		}
		pend = append(pend, pending{ln: ln, target: f.Target})
	}
	if socksAddr != "" {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			return fail(fmt.Errorf("socks5 %s: %w", socksAddr, err))
		}
		pend = append(pend, pending{ln: ln, socks: true})
	}
	for _, p := range pend {
		a.lns = append(a.lns, p.ln)
		if p.socks {
			st := &SOCKS5Status{Listen: p.ln.Addr().String(), State: "listening"}
			a.socks = st
			s5 := &socks5.Server{
				Logf: func(format string, args ...any) { log.Debug(formatMsg(format, args...)) },
				Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dial.DialContext(ctx, network, addr)
				},
			}
			a.wg.Add(1)
			go func(ln net.Listener) {
				defer a.wg.Done()
				if err := s5.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Debug("socks5 serve ended", "err", err)
				}
			}(p.ln)
			continue
		}
		a.forwards = append(a.forwards, ForwardStatus{Listen: p.ln.Addr().String(), Target: p.target, State: "listening"})
		a.wg.Add(1)
		go a.acceptLoop(p.ln, p.target)
	}
	return a, nil
}

func (a *LocalAccess) acceptLoop(ln net.Listener, target string) {
	defer a.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			_ = c.Close()
			return
		}
		a.wg.Add(1)
		a.mu.Unlock()
		go func() {
			defer a.wg.Done()
			a.serveConn(c, target)
		}()
	}
}

func (a *LocalAccess) serveConn(client net.Conn, target string) {
	defer func() { _ = client.Close() }()
	if !a.track(client) {
		return
	}
	defer a.untrack(client)
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	upstream, err := a.dial.DialContext(ctx, "tcp", target)
	if err != nil {
		a.log.Debug("forward dial failed", "target", target, "err", err)
		return
	}
	defer func() { _ = upstream.Close() }()
	if !a.track(upstream) {
		return
	}
	defer a.untrack(upstream)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(upstream, client) }()
	go func() { defer wg.Done(); copyHalf(client, upstream) }()
	wg.Wait()
}

// dialUpstream cancels the dial when the daemon stops, the timeout fires, or
// the client goes away. The watch is armed before DialContext and stopped
// before the byte copy, so it does not run for the life of the session.
func (a *LocalAccess) dialUpstream(client net.Conn, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(a.ctx, a.dialTimeout)
	defer cancel()
	stop := watchDisconnect(client, cancel)
	defer stop()
	return a.dial.DialContext(ctx, "tcp", target)
}

func (a *LocalAccess) gateOpen() bool {
	if a.gate == nil {
		return true
	}
	return a.gate()
}

func (a *LocalAccess) track(c net.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		_ = c.Close()
		return false
	}
	a.conns[c] = struct{}{}
	return true
}

func (a *LocalAccess) untrack(c net.Conn) {
	a.mu.Lock()
	delete(a.conns, c)
	a.mu.Unlock()
}

// copyHalf copies src to dst and then half-closes dst so the peer observes
// EOF while the opposite direction can still deliver a response.
func copyHalf(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// Close stops listeners, unblocks in-flight dials and copies, and waits until
// the accept loops and connection goroutines have returned.
func (a *LocalAccess) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	lns := append([]net.Listener(nil), a.lns...)
	conns := make([]net.Conn, 0, len(a.conns))
	for c := range a.conns {
		conns = append(conns, c)
	}
	for i := range a.forwards {
		a.forwards[i].State = "closed"
	}
	if a.socks != nil {
		a.socks.State = "closed"
	}
	a.mu.Unlock()
	a.cancel()
	for _, ln := range lns {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	a.wg.Wait()
	return nil
}

// ForwardStatus returns a copy of the forward rows.
func (a *LocalAccess) ForwardStatus() []ForwardStatus {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ForwardStatus, len(a.forwards))
	copy(out, a.forwards)
	return out
}

// SOCKS5Status returns a copy, or nil when SOCKS5 is not configured.
func (a *LocalAccess) SOCKS5Status() *SOCKS5Status {
	if a == nil || a.socks == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := *a.socks
	return &cp
}

// runtimeSprintf is fmt.Sprintf through a variable so go vet does not require
// the format argument to be a constant. tsnet and the SOCKS5 server pass a
// runtime format string.
var runtimeSprintf = fmt.Sprintf

func formatMsg(format string, args ...any) string {
	return runtimeSprintf(format, args...)
}
