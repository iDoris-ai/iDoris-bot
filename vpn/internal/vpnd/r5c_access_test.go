package vpnd

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
)

// TestR5CBindConflictRetriesAndMembershipConnects occupies a loopback port,
// starts access and a membership reconciler, and checks that the bind failure
// is reported while the node still reaches Running. Freeing the port lets the
// retry bind, and the status error clears. A relative unix path still fails
// before any socket is opened.
func TestR5CBindConflictRetriesAndMembershipConnects(t *testing.T) {
	prev := accessRetryInterval
	accessRetryInterval = 20 * time.Millisecond
	t.Cleanup(func() { accessRetryInterval = prev })

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := occupied.Addr().String()
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksAddr := socksLn.Addr().String()

	if _, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "unix:relative", Target: "127.0.0.1:9"}}, "", AccessOptions{}, nil); err == nil {
		t.Fatal("relative unix path was accepted")
	}

	access, err := StartAccess(&net.Dialer{}, []Forward{{Listen: addr, Target: "127.0.0.1:9"}}, socksAddr, AccessOptions{AllowAnonymous: true}, nil)
	if err != nil {
		t.Fatalf("bind conflict stopped access: %v", err)
	}
	t.Cleanup(func() { _ = access.Close() })

	got := access.AccessError()
	if !strings.Contains(got, addr) || !strings.Contains(got, socksAddr) || !strings.Contains(strings.ToLower(got), "bind") {
		t.Fatalf("access_error %q", got)
	}
	fw := access.ForwardStatus()
	if len(fw) != 1 || fw[0].State != "failed" || !strings.Contains(fw[0].Listen, addr) {
		t.Fatalf("forward status %+v", fw)
	}
	if s5 := access.SOCKS5Status(); s5 == nil || s5.State != "failed" || !strings.Contains(s5.Listen, socksAddr) {
		t.Fatalf("socks5 status %+v", s5)
	}

	be := &fakeBackend{state: ipn.NeedsLogin}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	if snap, err := r.Step(context.Background()); err != nil || snap.Phase == PhaseConnected {
		t.Fatalf("first step %+v %v", snap, err)
	}
	be.state = ipn.Running
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected {
		t.Fatalf("membership while listener is down: %+v %v", snap, err)
	}
	if access.AccessError() == "" {
		t.Fatal("access_error cleared before the port was released")
	}
	view := View{Source: stubStatus{snap: snap}, Access: access}.Snapshot()
	if view.Phase != PhaseConnected || view.AccessError == "" {
		t.Fatalf("status phase %s access_error %q", view.Phase, view.AccessError)
	}
	text := FormatStatus(map[string]any{
		"phase":        string(view.Phase),
		"access_error": view.AccessError,
	})
	if !strings.Contains(text, "access_error:") || !strings.Contains(text, addr) {
		t.Fatalf("status text:\n%s", text)
	}

	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := socksLn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if access.AccessError() == "" {
			fw = access.ForwardStatus()
			if len(fw) == 1 && fw[0].State == "listening" {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if access.AccessError() != "" {
		t.Fatalf("access_error after release: %q", access.AccessError())
	}
	fw = access.ForwardStatus()
	if len(fw) != 1 || fw[0].State != "listening" {
		t.Fatalf("forward after release %+v", fw)
	}
	s5 := access.SOCKS5Status()
	if s5 == nil || s5.State != "listening" {
		t.Fatalf("socks5 after release %+v", s5)
	}
	conn, err := net.DialTimeout("tcp", fw[0].Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	cleared := View{Source: stubStatus{snap: snap}, Access: access}.Snapshot()
	if cleared.AccessError != "" {
		t.Fatalf("status still reports %q", cleared.AccessError)
	}
}
