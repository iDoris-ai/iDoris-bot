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
)

// Dialer is how local listeners reach a tailnet address. *net.Dialer satisfies
// it for system mode (the kernel routes tailnet IPs). The embedded node
// satisfies it with tsnet, which also resolves MagicDNS names.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ForwardStatus is one local forward as reported by the status API.
type ForwardStatus struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
	State  string `json:"state"`
	// Error is set when State is "failed".
	Error string `json:"error,omitempty"`
}

// SOCKS5Status is the optional local SOCKS5 listener.
type SOCKS5Status struct {
	Listen string `json:"listen"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
	// AuthFile is the credential file when SOCKS5 is authenticated.
	// Empty for an anonymous listener. The password is never included.
	AuthFile string `json:"auth_file,omitempty"`
}

// AccessOptions controls every listener started by StartAccess.
// Zero MaxConnections means defaultMaxConnections (64). Zero DialTimeout
// means defaultDialTimeout (10s). A nil Gate is always open.
type AccessOptions struct {
	MaxConnections int
	DialTimeout    time.Duration
	// Gate reports whether new connections may dial. Closed means the node is
	// not on our tailnet, or the enrollment identity is not confirmed. The
	// daemon wires the function; this package only enforces it.
	Gate func() bool
	// Owner, when set, is consulted instead of Gate and ties every accepted
	// connection to an ownership generation. A lost generation cancels dials
	// and closes streams already in progress.
	Owner *LiveOwner
	// SOCKS5User and SOCKS5Password are the RFC 1929 credential. Both empty
	// means "look at the auth file". Setting only one is an error.
	SOCKS5User     string
	SOCKS5Password string
	// AllowAnonymous permits a SOCKS5 listener with no authentication.
	// StartLocalAccess sets it so the existing daemon keeps working.
	AllowAnonymous bool
	// SOCKS5AuthFile is a 0600 file containing one "user:password" line.
	SOCKS5AuthFile string
	// StateDir, when set and SOCKS5AuthFile is empty, holds socks5.auth.
	// The file is created mode 0600 on first use and reused after a restart.
	StateDir string
	// listenHook wraps a listener before its accept loop. Tests use it to
	// inject Accept errors. Production leaves it nil.
	listenHook func(net.Listener) net.Listener
}

const (
	defaultMaxConnections = 64
	defaultDialTimeout    = 10 * time.Second
	acceptBackoffStart    = 5 * time.Millisecond
	acceptBackoffMax      = time.Second
)

// anonymousSOCKSWarning is logged when a SOCKS5 listener has no authentication.
const anonymousSOCKSWarning = "SOCKS5 allows anonymous local access: every local user, and for an HTTP service a web page via DNS rebinding, can use this node's tailnet identity"

// LocalAccess is the set of local forwards and the optional SOCKS5 proxy.
// It dials through Dialer and does not know whether that dialer is tsnet or
// the kernel.
type LocalAccess struct {
	dial        Dialer
	log         *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	gate        func() bool
	owner       *LiveOwner
	dialTimeout time.Duration
	user        string
	pass        string
	authFile    string

	mu     sync.Mutex
	closed bool
	bounds []bound
	conns  map[net.Conn]uint64
	// dialCancel aborts an in-flight dial when its admission generation is
	// revoked. Closing the net.Conn is not enough: watchDisconnect holds a
	// duplicate of the socket, so the peer stays up until the dial returns
	// and that duplicate is closed.
	dialCancel map[net.Conn]context.CancelFunc
	wg         sync.WaitGroup
}

type bound struct {
	ln      net.Listener
	target  string
	socks   bool
	listen  string
	state   string
	errText string
	used    int
	max     int
}

// startLocalAccess opens an anonymous SOCKS5 listener. Nothing in the daemon
// wiring calls it. cmd/idoris-vpnd uses StartAccess and sets AllowAnonymous
// only from the explicit socks5_allow_anonymous config. The helper remains so
// tests can open the old listener. A non-nil logger receives
// anonymousSOCKSWarning when socksAddr is set.
func startLocalAccess(dial Dialer, forwards []Forward, socksAddr string, log *slog.Logger) (*LocalAccess, error) {
	return StartAccess(dial, forwards, socksAddr, AccessOptions{AllowAnonymous: true}, log)
}

// StartAccess listens on each forward and on socksAddr (empty disables
// SOCKS5). A port of 0 selects an ephemeral port and the status reports the
// bound address. A nil dialer or a listen error fails the call and leaves
// nothing running.
func StartAccess(dial Dialer, forwards []Forward, socksAddr string, opt AccessOptions, log *slog.Logger) (*LocalAccess, error) {
	if len(forwards) == 0 && socksAddr == "" {
		return nil, nil
	}
	if dial == nil {
		return nil, errors.New("vpnd: dialer is required for forwards")
	}
	callerLog := log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	maxConn := opt.MaxConnections
	if maxConn == 0 {
		maxConn = defaultMaxConnections
	}
	if maxConn < 0 {
		return nil, errors.New("vpnd: max_connections must be >= 0")
	}
	dialTimeout := opt.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}
	if dialTimeout < 0 {
		return nil, errors.New("vpnd: dial_timeout must be >= 0")
	}
	var user, pass, authFile string
	if socksAddr != "" {
		var anon, created bool
		var err error
		user, pass, anon, authFile, created, err = resolveSOCKSAuth(opt)
		if err != nil {
			return nil, err
		}
		if anon && callerLog != nil {
			callerLog.Warn(anonymousSOCKSWarning)
		}
		// The path only. The password stays in the 0600 file.
		if created && callerLog != nil {
			callerLog.Info("SOCKS5 auth file created", "path", authFile)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &LocalAccess{
		dial:        dial,
		log:         log,
		ctx:         ctx,
		cancel:      cancel,
		gate:        opt.Gate,
		owner:       opt.Owner,
		dialTimeout: dialTimeout,
		user:        user,
		pass:        pass,
		authFile:    authFile,
		conns:       map[net.Conn]uint64{},
		dialCancel:  map[net.Conn]context.CancelFunc{},
	}
	if opt.Owner != nil {
		opt.Owner.SetOnLost(func() { a.closeStale() })
	}
	fail := func(err error) (*LocalAccess, error) {
		for _, b := range a.bounds {
			_ = b.ln.Close()
		}
		cancel()
		return nil, err
	}
	add := func(network, address, target string, socks bool) error {
		ln, err := listenLocal(network, address)
		if err != nil {
			return err
		}
		if opt.listenHook != nil {
			if wrapped := opt.listenHook(ln); wrapped != nil {
				ln = wrapped
			}
		}
		a.bounds = append(a.bounds, bound{
			ln:     ln,
			target: target,
			socks:  socks,
			listen: ln.Addr().String(),
			state:  "listening",
			max:    maxConn,
		})
		return nil
	}
	for _, f := range forwards {
		network, address, err := splitListen(f.Listen)
		if err != nil {
			return fail(fmt.Errorf("forward %s -> %s: %w", f.Listen, f.Target, err))
		}
		if network == "unix" {
			if err := prepareUnixSocket(address); err != nil {
				return fail(fmt.Errorf("forward %s -> %s: %w", f.Listen, f.Target, err))
			}
		}
		if err := add(network, address, f.Target, false); err != nil {
			return fail(fmt.Errorf("forward %s -> %s: %w", f.Listen, f.Target, err))
		}
	}
	if socksAddr != "" {
		network, address, err := splitListen(socksAddr)
		if err != nil {
			return fail(fmt.Errorf("socks5 %s: %w", socksAddr, err))
		}
		if network == "unix" {
			if err := prepareUnixSocket(address); err != nil {
				return fail(fmt.Errorf("socks5 %s: %w", socksAddr, err))
			}
		}
		if err := add(network, address, "", true); err != nil {
			return fail(fmt.Errorf("socks5 %s: %w", socksAddr, err))
		}
	}
	if a.owner != nil {
		a.wg.Add(1)
		go a.watchOwner()
	}
	for i := range a.bounds {
		a.wg.Add(1)
		go a.acceptLoop(i)
	}
	return a, nil
}

// watchOwner polls LocalAPI on the ownership cache interval and also wakes
// when the reconciler bumps the generation. Streams accepted under an older
// generation are closed as soon as the gate is shut, including dials that
// have not returned yet (those watch the same generation from dialUpstream).
func (a *LocalAccess) watchOwner() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.owner.TTL())
	defer ticker.Stop()
	for {
		// A bump that landed before this goroutine subscribed, or while
		// Poll was running, is still applied here. Reopen does not spare
		// streams admitted under the generation that ended.
		a.closeStale()
		ch := a.owner.WaitCh()
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.owner.Poll(a.ctx)
		case <-ch:
		}
	}
}

func (a *LocalAccess) acceptLoop(idx int) {
	defer a.wg.Done()
	backoff := acceptBackoffStart
	for {
		a.mu.Lock()
		ln := a.bounds[idx].ln
		stopped := a.closed
		a.mu.Unlock()
		if stopped {
			return
		}
		c, err := ln.Accept()
		if err != nil {
			if a.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			if isTemporaryAccept(err) {
				a.log.Debug("accept retry", "err", err)
				if !a.sleep(backoff) {
					return
				}
				if backoff < acceptBackoffMax {
					backoff *= 2
				}
				continue
			}
			a.failListener(idx, err)
			return
		}
		backoff = acceptBackoffStart
		admitGen, open := a.admit()
		if !open {
			_ = c.Close()
			continue
		}
		if !a.acquire(idx) {
			_ = c.Close()
			continue
		}
		go func() {
			defer a.release(idx)
			a.serveAccepted(c, idx, admitGen)
		}()
	}
}

// admit records the ownership generation under which this connection may
// proceed. A generation that moves while the check runs is not admitted:
// the next accept observes the new one. Owner nil keeps the plain gate.
func (a *LocalAccess) admit() (uint64, bool) {
	if a.owner == nil {
		if a.gate == nil || a.gate() {
			return 0, true
		}
		return 0, false
	}
	gen := a.owner.Generation()
	if !a.owner.Allow() {
		return 0, false
	}
	if a.owner.Generation() != gen {
		return 0, false
	}
	return gen, true
}

func (a *LocalAccess) serveAccepted(client net.Conn, idx int, admitGen uint64) {
	a.mu.Lock()
	socks := a.bounds[idx].socks
	target := a.bounds[idx].target
	a.mu.Unlock()
	if socks {
		a.serveSOCKS(client, admitGen)
		return
	}
	a.serveConn(client, target, admitGen)
}

func (a *LocalAccess) serveConn(client net.Conn, target string, admitGen uint64) {
	defer func() { _ = client.Close() }()
	if !a.track(client, admitGen) {
		return
	}
	defer a.untrack(client)
	if !a.generationLive(admitGen) {
		return
	}
	upstream, err := a.dialUpstream(client, target, admitGen)
	if err != nil {
		a.log.Debug("forward dial failed", "target", target, "err", err)
		return
	}
	defer func() { _ = upstream.Close() }()
	if !a.track(upstream, admitGen) {
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
func (a *LocalAccess) dialUpstream(client net.Conn, target string, admitGen uint64) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(a.ctx, a.dialTimeout)
	defer cancel()
	a.armDial(client, cancel, admitGen)
	defer a.disarmDial(client)
	stop := watchDisconnect(client, cancel)
	defer stop()
	a.watchLost(ctx, cancel, admitGen)
	return a.dial.DialContext(ctx, "tcp", target)
}

// armDial lets closeStale cancel this dial. A generation that is already
// obsolete cancels immediately, before DialContext.
func (a *LocalAccess) armDial(c net.Conn, cancel context.CancelFunc, admitGen uint64) {
	// Generation is read outside a.mu. closeStale takes the owner lock and
	// then a.mu, so the opposite order deadlocks.
	a.mu.Lock()
	closed := a.closed
	if !closed {
		a.dialCancel[c] = cancel
	}
	a.mu.Unlock()
	if closed || (a.owner != nil && a.owner.Generation() != admitGen) {
		a.disarmDial(c)
		cancel()
	}
}

func (a *LocalAccess) disarmDial(c net.Conn) {
	a.mu.Lock()
	delete(a.dialCancel, c)
	a.mu.Unlock()
}

// watchLost cancels a dial when the ownership generation is no longer the
// one this connection was admitted under. A gate that closed and reopened
// under another identity still cancels: Allow can be true again while this
// dial belongs to the previous generation. The generation is read again
// after WaitCh so a bump between the two is not lost.
func (a *LocalAccess) watchLost(ctx context.Context, cancel context.CancelFunc, admitGen uint64) {
	if a.owner == nil {
		return
	}
	go func() {
		for {
			if a.owner.Generation() != admitGen {
				cancel()
				return
			}
			ch := a.owner.WaitCh()
			if a.owner.Generation() != admitGen {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}
		}
	}()
}

// generationLive reports whether admitGen is still the current ownership
// generation. With no owner the plain gate decides.
func (a *LocalAccess) generationLive(admitGen uint64) bool {
	if a.owner == nil {
		return a.gateOpen()
	}
	return a.owner.Generation() == admitGen && a.owner.Allow()
}

// closeStale closes connections admitted under a generation that is not the
// current one. A reopen does not spare them: their generation is obsolete
// even if the gate is open again.
func (a *LocalAccess) closeStale() {
	if a.owner == nil {
		return
	}
	current := a.owner.Generation()
	a.mu.Lock()
	conns := make([]net.Conn, 0, len(a.conns))
	cancels := make([]context.CancelFunc, 0, len(a.dialCancel))
	for c, gen := range a.conns {
		if gen == current {
			continue
		}
		conns = append(conns, c)
		if cancel, ok := a.dialCancel[c]; ok {
			cancels = append(cancels, cancel)
			delete(a.dialCancel, c)
		}
	}
	a.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func (a *LocalAccess) acquire(idx int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	b := &a.bounds[idx]
	if b.used >= b.max {
		return false
	}
	b.used++
	a.wg.Add(1)
	return true
}

func (a *LocalAccess) release(idx int) {
	a.mu.Lock()
	a.bounds[idx].used--
	a.mu.Unlock()
	a.wg.Done()
}

func (a *LocalAccess) failListener(idx int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.bounds[idx].state = "failed"
	a.bounds[idx].errText = err.Error()
	a.log.Error("listener failed", "listen", a.bounds[idx].listen, "err", err)
}

func (a *LocalAccess) stopping() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *LocalAccess) gateOpen() bool {
	if a.owner != nil {
		return a.owner.Allow()
	}
	if a.gate == nil {
		return true
	}
	return a.gate()
}

func (a *LocalAccess) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-a.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (a *LocalAccess) track(c net.Conn, admitGen uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		_ = c.Close()
		return false
	}
	a.conns[c] = admitGen
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
	lns := make([]net.Listener, len(a.bounds))
	conns := make([]net.Conn, 0, len(a.conns))
	for i := range a.bounds {
		lns[i] = a.bounds[i].ln
		if a.bounds[i].state != "failed" {
			a.bounds[i].state = "closed"
		}
	}
	for c := range a.conns {
		conns = append(conns, c)
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

// Suspended reports whether the gate is closed. A nil access is not suspended.
// A failed listener still reports the gate; ForwardStatus keeps "failed".
func (a *LocalAccess) Suspended() bool {
	if a == nil {
		return false
	}
	return !a.gateOpen()
}

func (a *LocalAccess) snapshot() (rows []ForwardStatus, socks *SOCKS5Status, suspended bool) {
	a.mu.Lock()
	rows = make([]ForwardStatus, 0, len(a.bounds))
	for _, b := range a.bounds {
		st := ForwardStatus{Listen: b.listen, Target: b.target, State: b.state, Error: b.errText}
		if b.socks {
			socks = &SOCKS5Status{Listen: b.listen, State: b.state, Error: b.errText, AuthFile: a.authFile}
			continue
		}
		rows = append(rows, st)
	}
	a.mu.Unlock()
	suspended = !a.gateOpen()
	if !suspended {
		return rows, socks, false
	}
	for i := range rows {
		if rows[i].State == "listening" {
			rows[i].State = "suspended"
		}
	}
	if socks != nil && socks.State == "listening" {
		socks.State = "suspended"
	}
	return rows, socks, true
}

// ForwardStatus returns a copy of the forward rows.
func (a *LocalAccess) ForwardStatus() []ForwardStatus {
	if a == nil {
		return nil
	}
	rows, _, _ := a.snapshot()
	return rows
}

// SOCKS5Status returns a copy, or nil when SOCKS5 is not configured.
func (a *LocalAccess) SOCKS5Status() *SOCKS5Status {
	if a == nil {
		return nil
	}
	_, socks, _ := a.snapshot()
	return socks
}

// runtimeSprintf is fmt.Sprintf through a variable so go vet does not require
// the format argument to be a constant. tsnet passes a runtime format string.
var runtimeSprintf = fmt.Sprintf

func formatMsg(format string, args ...any) string {
	return runtimeSprintf(format, args...)
}
