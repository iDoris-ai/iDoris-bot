package vpnd

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestR3c2TCPListenerWarnsAnyLocalUser(t *testing.T) {
	var buf bytes.Buffer
	restore := r3c2CaptureDefaultLog(t, &buf)
	defer restore()
	setOwnerOnlyListens(nil)

	ln, err := listenLocal("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !bytes.Contains(buf.Bytes(), []byte("any local user")) {
		t.Fatalf("TCP listener did not warn: %s", buf.Bytes())
	}
	if !bytes.Contains(buf.Bytes(), []byte(ln.Addr().String())) {
		t.Fatalf("warning missing bound address %s: %s", ln.Addr(), buf.Bytes())
	}

	buf.Reset()
	dir := shortSockDir(t)
	uln, err := listenLocal("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer uln.Close()
	if bytes.Contains(buf.Bytes(), []byte("any local user")) {
		t.Fatalf("unix listener warned: %s", buf.Bytes())
	}
}

func TestR3c2StartAccessWarnsOnTCPForward(t *testing.T) {
	var buf bytes.Buffer
	restore := r3c2CaptureDefaultLog(t, &buf)
	defer restore()
	setOwnerOnlyListens(nil)

	access, err := StartLocalAccess(&net.Dialer{}, []Forward{{Listen: "127.0.0.1:0", Target: "peer:1"}}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	if !bytes.Contains(buf.Bytes(), []byte("any local user")) {
		t.Fatalf("StartAccess TCP forward did not warn: %s", buf.Bytes())
	}

	buf.Reset()
	dir := shortSockDir(t)
	uaccess, err := StartLocalAccess(&net.Dialer{}, []Forward{{Listen: "unix:" + filepath.Join(dir, "s"), Target: "peer:1"}}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer uaccess.Close()
	if bytes.Contains(buf.Bytes(), []byte("any local user")) {
		t.Fatalf("unix forward warned: %s", buf.Bytes())
	}
}

func TestR3c2OwnerOnlyPlatformGate(t *testing.T) {
	prev := ownerOnlySupported
	t.Cleanup(func() {
		ownerOnlySupported = prev
		setOwnerOnlyListens(nil)
	})

	tcp := &Config{Forwards: []Forward{{Listen: "127.0.0.1:9", Target: "h:1", OwnerOnly: true}}}
	ownerOnlySupported = false
	err := tcp.validateForwards()
	if err == nil || !strings.Contains(err.Error(), "owner_only") || !strings.Contains(err.Error(), "unix:") {
		t.Fatalf("TCP owner_only on an OS without a reliable peer uid: %v", err)
	}
	if ownerOnlyEnforced("127.0.0.1:9") {
		t.Fatal("rejected owner_only armed the listener")
	}

	ownerOnlySupported = true
	if err := tcp.validateForwards(); err != nil {
		t.Fatal(err)
	}
	if !ownerOnlyEnforced("127.0.0.1:9") {
		t.Fatal("linux TCP owner_only was not armed")
	}

	dir := shortSockDir(t)
	unixAddr := "unix:" + filepath.Join(dir, "s")
	ownerOnlySupported = false
	unixCfg := &Config{Forwards: []Forward{{Listen: unixAddr, Target: "h:1", OwnerOnly: true}}}
	if err := unixCfg.validateForwards(); err != nil {
		t.Fatalf("unix owner_only is a no-op, got %v", err)
	}
	if ownerOnlyEnforced(unixAddr) || ownerOnlyEnforced("127.0.0.1:9") {
		t.Fatal("unix owner_only armed a TCP filter or left the previous one in place")
	}
}

func TestR3c2OwnerOnlyRejectsOtherUID(t *testing.T) {
	prevSupported := ownerOnlySupported
	prevLookup := peerUIDFunc
	t.Cleanup(func() {
		ownerOnlySupported = prevSupported
		peerUIDFunc = prevLookup
		setOwnerOnlyListens(nil)
	})
	ownerOnlySupported = true
	const addr = "127.0.0.1:0"
	setOwnerOnlyListens([]string{addr})

	var mu sync.Mutex
	uid := os.Getuid() + 1
	peerUIDFunc = func(net.Conn) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return uid, nil
	}

	var buf bytes.Buffer
	restore := r3c2CaptureDefaultLog(t, &buf)
	defer restore()

	ln, err := listenLocal("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if bytes.Contains(buf.Bytes(), []byte("any local user")) {
		t.Fatalf("enforced owner_only still warned: %s", buf.Bytes())
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	reject, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer reject.Close()
	if err := r3c2ExpectClosed(reject); err != nil {
		t.Fatalf("other uid connection stayed open: %v", err)
	}

	mu.Lock()
	uid = os.Getuid()
	mu.Unlock()
	allow, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer allow.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("owner connection was not accepted")
	}

	// A lookup error is fail-closed: the connection is closed and Accept waits.
	peerUIDFunc = func(net.Conn) (int, error) {
		return 0, fmt.Errorf("proc unreadable")
	}
	bad, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := r3c2ExpectClosed(bad); err != nil {
		t.Fatalf("lookup failure left the connection open: %v", err)
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("lookup failure was returned from Accept")
	case <-time.After(200 * time.Millisecond):
	}
}

func r3c2ExpectClosed(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		return fmt.Errorf("read succeeded")
	}
	if time.Since(start) > time.Second {
		return fmt.Errorf("not closed promptly: %w", err)
	}
	return nil
}

func TestR3c2ProcPeerUID(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	server := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
	local, err := procEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := procEndpoint(server)
	if err != nil {
		t.Fatal(err)
	}
	if local != "0100007F:9C40" || remote != "0100007F:0438" {
		t.Fatalf("endpoints local=%s remote=%s", local, remote)
	}
	v6, err := procEndpoint(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	if v6 != "00000000000000000000000001000000:0001" {
		t.Fatalf("ipv6 endpoint %s", v6)
	}

	// The server row is swapped and carries the daemon uid. Only the client row counts.
	body := fmt.Sprintf("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: %s %s 01 00000000:00000000 00:00000000 00000000     0        0 1 1 00000000 20 4 30 10 -1\n   1: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 00000000 20 4 30 10 -1\n", remote, local, local, remote)
	uid, err := uidFromProc([]byte(body), local, remote)
	if err != nil || uid != 1000 {
		t.Fatalf("uid=%d err=%v", uid, err)
	}
	ambiguous := body + fmt.Sprintf("   2: %s %s 01 00000000:00000000 00:00000000 00000000  1001        0 3 1 00000000 20 4 30 10 -1\n", local, remote)
	if _, err := uidFromProc([]byte(ambiguous), local, remote); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := uidFromProc([]byte(body), local, "0100007F:0001"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}

	// Snapshot built from a live connection's addresses, read through the real parser.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	liveLocal, err := procEndpoint(serverConn.RemoteAddr())
	if err != nil {
		t.Fatal(err)
	}
	liveRemote, err := procEndpoint(serverConn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	snap := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000    42        0 9 1 00000000 20 4 30 10 -1\n   1: %s %s 01 00000000:00000000 00:00000000 00000000     7        0 8 1 00000000 20 4 30 10 -1\n", liveLocal, liveRemote, liveRemote, liveLocal)
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	prevTCP := procNetTCP
	procNetTCP = path
	t.Cleanup(func() { procNetTCP = prevTCP })
	got, err := peerUIDFromProc(serverConn)
	if err != nil || got != 42 {
		t.Fatalf("live snapshot uid=%d err=%v (local %s remote %s)", got, err, liveLocal, liveRemote)
	}
	if runtime.GOOS == "linux" && prevTCP != "/proc/net/tcp" {
		t.Fatalf("production proc path was %s", prevTCP)
	}
}

func r3c2CaptureDefaultLog(t *testing.T, buf *bytes.Buffer) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	return func() { slog.SetDefault(prev) }
}
