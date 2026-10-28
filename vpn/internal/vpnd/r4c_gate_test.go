package vpnd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestR4CStaleOwnershipEvaluationIsDiscarded blocks one evaluation, bumps
// the generation, and lets a second evaluation publish a closed decision.
// The blocked evaluation then returns allow. That result must not be cached
// and must not be returned as permission.
func TestR4CStaleOwnershipEvaluationIsDiscarded(t *testing.T) {
	o := NewLiveOwner(LiveOwnerConfig{
		Mode:       ModeEmbedded,
		OurControl: ours,
		CacheTTL:   time.Hour,
		Snapshot:   func() Snapshot { return Snapshot{Phase: PhaseConnected, CurrentControl: ours} },
	})
	wall := time.Now()
	o.now = func() time.Time { return wall }
	var n int
	var mu sync.Mutex
	first := make(chan struct{})
	release := make(chan struct{})
	o.eval = func(context.Context) bool {
		mu.Lock()
		n++
		call := n
		mu.Unlock()
		if call == 1 {
			return true
		}
		if call == 2 {
			close(first)
			<-release
			return true
		}
		return false
	}
	if !o.Allow() {
		t.Fatal("prime")
	}
	wall = wall.Add(2 * time.Hour)
	stale := make(chan bool, 1)
	go func() { stale <- o.Allow() }()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("evaluation did not start")
	}
	o.Bump()
	if o.Allow() {
		t.Fatal("evaluation after the bump was allowed")
	}
	close(release)
	select {
	case ok := <-stale:
		if ok {
			t.Fatal("stale evaluation was returned as permission")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale evaluation did not finish")
	}
	if o.Allow() {
		t.Fatal("stale allow overwrote the closed decision")
	}
}

// TestR4COlderEvaluationDoesNotOverwrite starts two evaluations at the same
// generation. The later one publishes closed. The earlier one finishing
// afterwards with allow must leave the closed decision in place.
func TestR4COlderEvaluationDoesNotOverwrite(t *testing.T) {
	o := NewLiveOwner(LiveOwnerConfig{
		Mode:       ModeEmbedded,
		OurControl: ours,
		CacheTTL:   time.Hour,
		Snapshot:   func() Snapshot { return Snapshot{Phase: PhaseConnected, CurrentControl: ours} },
	})
	var n int
	var mu sync.Mutex
	first := make(chan struct{})
	release := make(chan struct{})
	secondDone := make(chan struct{})
	o.eval = func(context.Context) bool {
		mu.Lock()
		n++
		call := n
		mu.Unlock()
		if call == 1 {
			close(first)
			<-release
			return true
		}
		close(secondDone)
		return false
	}
	stale := make(chan bool, 1)
	go func() { stale <- o.Allow() }()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("first evaluation did not start")
	}
	if o.Allow() {
		t.Fatal("newer evaluation was allowed")
	}
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("newer evaluation did not finish")
	}
	close(release)
	select {
	case ok := <-stale:
		if ok {
			t.Fatal("older evaluation was returned as permission")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("older evaluation did not finish")
	}
	if o.Allow() {
		t.Fatal("older allow overwrote the newer closed decision")
	}
}
