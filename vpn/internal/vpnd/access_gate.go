package vpnd

import (
	"context"
	"sync"
	"time"

	"tailscale.com/ipn"
)

// OwnershipCacheTTL is the longest a live ownership check may be reused.
// Forwards dial through the kernel, so a stale "open" answer is a window
// onto whatever tailnet is installed right now. One second is the ceiling.
const OwnershipCacheTTL = time.Second

// AccessOpen reports whether a local forward or SOCKS5 listener may dial.
// Embedded and system mode both require a confirmed identity, the live
// control URL to be ours, and a phase that still carries traffic.
// Embedded mode used to stay open regardless; an old admin node stayed
// reachable through forwards after enrollment to the new credential failed.
// Snapshot.ControlURL is always the URL this daemon wants; pass the live
// control URL. Any other mode is closed. identityConfirmed is false while
// an identity transition is in progress or the binding does not name the
// running node.
func AccessOpen(mode, currentControl, ourControl string, phase Phase, identityConfirmed bool) bool {
	if !identityConfirmed {
		return false
	}
	if mode != ModeEmbedded && mode != ModeSystem {
		return false
	}
	if !SameControlURL(currentControl, ourControl) {
		return false
	}
	return phase == PhaseConnected || phase == PhaseRoutesPending
}

// LiveOwnerConfig is the live half of the access gate. Backend is the
// LocalAPI the forwards would dial through. Snapshot and Identity are read
// on each refresh; both must be safe to call while the reconciler steps.
type LiveOwnerConfig struct {
	Backend    Backend
	Mode       string
	OurControl string
	State      *StateFile
	CacheTTL   time.Duration
	Snapshot   func() Snapshot
	// Identity reports whether nodeID and profileID are the confirmed
	// enrollment. Nil means "no opinion" and the gate then uses only the
	// snapshot phase, which is not enough for a profile switch.
	Identity func(nodeID, profileID string) bool
}

// LiveOwner is a fail-closed ownership generation. Allow is cached for at
// most OwnershipCacheTTL. Poll and a reconciler bump both invalidate that
// cache. Generation advances when the gate closes or the reconciler reports
// a phase, control, profile, or identity change. Connections captured under
// an older generation are closed by the listener that holds this owner.
type LiveOwner struct {
	be       Backend
	mode     string
	our      string
	state    *StateFile
	ttl      time.Duration
	snap     func() Snapshot
	identity func(nodeID, profileID string) bool
	now      func() time.Time

	mu       sync.Mutex
	gen      uint64
	waitCh   chan struct{}
	cachedOK bool
	cachedAt time.Time
	have     bool
	onLost   func()
	// evalSeq orders evaluations that overlap. appliedSeq is the newest
	// result that was allowed to update the cache. A result captured under
	// an older generation, or an older sequence, is discarded.
	evalSeq    uint64
	appliedSeq uint64
	// eval replaces evaluate in tests so one check can be held across a
	// generation change. Production leaves it nil.
	eval func(context.Context) bool
}

// NewLiveOwner builds a gate. A non-positive CacheTTL, or one above
// OwnershipCacheTTL, uses OwnershipCacheTTL.
func NewLiveOwner(cfg LiveOwnerConfig) *LiveOwner {
	ttl := cfg.CacheTTL
	if ttl <= 0 || ttl > OwnershipCacheTTL {
		ttl = OwnershipCacheTTL
	}
	return &LiveOwner{
		be:       cfg.Backend,
		mode:     cfg.Mode,
		our:      cfg.OurControl,
		state:    cfg.State,
		ttl:      ttl,
		snap:     cfg.Snapshot,
		identity: cfg.Identity,
		now:      time.Now,
		waitCh:   make(chan struct{}),
	}
}

// SetOnLost registers the callback invoked when the gate transitions to
// closed. It must not call Allow or Poll.
func (o *LiveOwner) SetOnLost(fn func()) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.onLost = fn
	o.mu.Unlock()
}

// TTL is the cache lifetime, also the poll interval the listener should use.
func (o *LiveOwner) TTL() time.Duration {
	if o == nil || o.ttl <= 0 {
		return OwnershipCacheTTL
	}
	return o.ttl
}

// Generation is the current ownership generation. A connection stores the
// value it observed when it was accepted.
func (o *LiveOwner) Generation() uint64 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.gen
}

// WaitCh closes when Generation changes. Call it again after each wake; the
// channel is replaced.
func (o *LiveOwner) WaitCh() <-chan struct{} {
	if o == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.waitCh
}

// Bump advances the generation and drops the cache. The reconciler calls it
// when phase, control URL, profile, or identity changes. The listener wakes,
// re-reads LocalAPI, and closes streams if the new answer is closed.
func (o *LiveOwner) Bump() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.bumpLocked()
	o.mu.Unlock()
}

func (o *LiveOwner) bumpLocked() {
	o.gen++
	o.have = false
	o.cachedOK = false
	close(o.waitCh)
	o.waitCh = make(chan struct{})
}

// Allow is the cached live check. A cache miss reads LocalAPI.
func (o *LiveOwner) Allow() bool {
	if o == nil {
		return true
	}
	return o.allow(context.Background(), false)
}

// Poll forces a live check, ignoring the cache. The listener calls it on
// each cache interval so an established stream does not outlive a tailnet
// switch by a full reconciler period.
func (o *LiveOwner) Poll(ctx context.Context) {
	if o == nil {
		return
	}
	_ = o.allow(ctx, true)
}

func (o *LiveOwner) allow(ctx context.Context, force bool) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	o.mu.Lock()
	if !force && o.have && o.now().Sub(o.cachedAt) < o.ttl {
		ok := o.cachedOK
		o.mu.Unlock()
		return ok
	}
	gen := o.gen
	o.evalSeq++
	seq := o.evalSeq
	eval := o.evaluate
	if o.eval != nil {
		eval = o.eval
	}
	o.mu.Unlock()
	ok := eval(ctx)
	return o.remember(ok, gen, seq)
}

// remember publishes ok only when this evaluation is still the newest one
// and the generation it observed is still current. A stale result is not
// cached and is not returned as permission.
func (o *LiveOwner) remember(ok bool, gen, seq uint64) bool {
	o.mu.Lock()
	if gen != o.gen || seq < o.appliedSeq {
		o.mu.Unlock()
		return false
	}
	o.appliedSeq = seq
	wasOpen := !o.have || o.cachedOK
	o.cachedOK = ok
	o.cachedAt = o.now()
	o.have = true
	var lost func()
	if !ok && wasOpen {
		// Advance once per close. Leaving the cache marked closed stops a
		// poll from bumping again on every tick while the tailnet stays foreign.
		o.gen++
		close(o.waitCh)
		o.waitCh = make(chan struct{})
		lost = o.onLost
	}
	o.mu.Unlock()
	if lost != nil {
		lost()
	}
	return ok
}

func (o *LiveOwner) evaluate(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	var snap Snapshot
	if o.snap != nil {
		snap = o.snap()
	}
	if o.be == nil {
		idOK := true
		if o.identity != nil {
			idOK = o.identity("", "")
		}
		return AccessOpen(o.mode, snap.CurrentControl, o.our, snap.Phase, idOK)
	}
	prefs, err := o.be.GetPrefs(ctx)
	if err != nil || prefs == nil {
		return false
	}
	st, err := o.be.Status(ctx)
	if err != nil || st == nil {
		return false
	}
	nodeID := ""
	if st.Self != nil {
		nodeID = string(st.Self.ID)
	}
	profileID := ""
	if o.mode == ModeSystem {
		if cur, _, perr := o.be.ProfileStatus(ctx); perr == nil {
			profileID = string(cur.ID)
		}
	}
	if o.state != nil {
		b := o.state.Get()
		if nodeID != "" && b.NodeID != "" && nodeID != b.NodeID {
			return false
		}
		if o.mode == ModeSystem && profileID != "" && b.ProfileID != "" && profileID != b.ProfileID {
			return false
		}
	}
	// A foreign control URL closes the gate even when the reconciler snapshot
	// still says connected. That snapshot is up to a poll interval old.
	if !SameControlURL(prefs.ControlURL, o.our) {
		return false
	}
	if st.BackendState != ipn.Running.String() {
		return false
	}
	idOK := true
	if o.identity != nil {
		idOK = o.identity(nodeID, profileID)
	}
	return AccessOpen(o.mode, prefs.ControlURL, o.our, snap.Phase, idOK)
}
