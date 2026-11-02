package vpnd

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
)

// TestR4CAdmissionGenerationSurvivesReopen admits a stream, then closes and
// reopens ownership before relying on the watcher. The old stream and its
// in-flight dial die even though Allow is true again. A connection admitted
// under the new generation stays up.
func TestR4CAdmissionGenerationSurvivesReopen(t *testing.T) {
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true},
	}
	owner := NewLiveOwner(LiveOwnerConfig{
		Backend:    be,
		Mode:       ModeEmbedded,
		OurControl: ours,
		CacheTTL:   20 * time.Millisecond,
		Snapshot: func() Snapshot {
			return Snapshot{Phase: PhaseConnected, CurrentControl: ours}
		},
		Identity: func(string, string) bool { return true },
	})
	var dials atomic.Int32
	started := make(chan struct{})
	var once sync.Once
	dialer := &callbackDialer{fn: func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := dials.Add(1)
		if n == 1 {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return a, nil
	}}
	access, err := StartAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "10.0.0.8:9"}}, "", AccessOptions{Owner: owner}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = access.Close() })
	addr := access.ForwardStatus()[0].Listen

	old, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not start")
	}
	// Close and reopen. Bump drops the cache and advances the generation.
	// The following Allow republishes open under the new generation, which
	// is what a watcher that only reacts to a closed gate would miss.
	owner.Bump()
	if !owner.Allow() {
		t.Fatal("gate did not reopen")
	}
	_ = old.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream admitted before the reopen was still readable")
	} else {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("stream admitted before the reopen was not closed")
		}
	}

	next, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	deadline := time.Now().Add(2 * time.Second)
	for dials.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if dials.Load() < 2 {
		t.Fatalf("new connection was not dialed: %d", dials.Load())
	}
	_ = next.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := next.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected payload")
	} else {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("connection admitted after the reopen was closed: %v", err)
		}
	}
}
