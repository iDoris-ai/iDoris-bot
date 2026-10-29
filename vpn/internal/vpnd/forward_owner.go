package vpnd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// tcpForwardWarning is logged for every TCP listener that does not enforce
// owner_only. A raw TCP forward has no protocol authentication, so any local
// user who can connect acts as this node. Unix listeners are mode 0600 and
// do not log this.
const tcpForwardWarning = "any local user can connect to this TCP listener and use this node's VPN identity. A raw TCP forward has no authentication; SOCKS5 still checks its own credentials. On a shared machine prefer a unix: listener (mode 0600)"

// ownerOnlySupported is false on darwin and windows. Verified on this Mac
// (2026-10-28): getsockopt LOCAL_PEERCRED / getpeereid on a TCP connection
// returns uid 0 with a nil error, so it cannot identify the peer. Windows
// has no equivalent lookup this process can rely on. Linux reads the uid
// column of /proc/net/tcp.
var ownerOnlySupported = runtime.GOOS == "linux"

var (
	procNetTCP  = "/proc/net/tcp"
	procNetTCP6 = "/proc/net/tcp6"
	// peerUIDFunc, when set, replaces the /proc lookup. Tests use it.
	// Production leaves it nil.
	peerUIDFunc func(net.Conn) (int, error)

	ownerOnlyMu  sync.Mutex
	ownerOnlySet = map[string]struct{}{}
)

// setOwnerOnlyListens replaces the TCP addresses whose listener must drop
// connections from other uids. The key is the address string listenLocal
// receives (the configured listen, including a :0 port).
func setOwnerOnlyListens(addrs []string) {
	next := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		next[a] = struct{}{}
	}
	ownerOnlyMu.Lock()
	ownerOnlySet = next
	ownerOnlyMu.Unlock()
}

func ownerOnlyEnforced(address string) bool {
	if !ownerOnlySupported {
		return false
	}
	ownerOnlyMu.Lock()
	_, ok := ownerOnlySet[address]
	ownerOnlyMu.Unlock()
	return ok
}

// ownerFilter accepts only connections whose peer uid is the daemon's uid.
// A failed lookup is rejected. Rejected connections are closed and not
// returned, so the accept loop keeps running.
type ownerFilter struct {
	net.Listener
	address string
}

func (l *ownerFilter) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := lookupPeerUID(c)
		if err != nil || uid != os.Getuid() {
			_ = c.Close()
			if err != nil {
				slog.Default().Warn("owner_only rejected a TCP connection", "listen", l.address, "err", err)
			} else {
				slog.Default().Warn("owner_only rejected a TCP connection", "listen", l.address, "peer_uid", uid)
			}
			continue
		}
		return c, nil
	}
}

func lookupPeerUID(c net.Conn) (int, error) {
	if peerUIDFunc != nil {
		return peerUIDFunc(c)
	}
	return peerUIDFromProc(c)
}

// peerUIDFromProc reads the client's row in /proc/net/tcp. The accepted
// conn's RemoteAddr is the client's local address; LocalAddr is the server.
// The kernel also has the server's row with those fields swapped and the
// daemon's own uid, so the match must use the client orientation.
//
// tcp4_seq_show fields after strings.Fields:
//
//	0 entry ("0:")
//	1 local HEXIP:HEXPORT
//	2 remote HEXIP:HEXPORT
//	3 state
//	4 tx_queue:rx_queue
//	5 tr:tm->when
//	6 retrnsmt
//	7 uid
//	8 timeout
//	9 inode
//
// IPv4 is a little-endian hex word (127.0.0.1 is 0100007F). IPv6 in
// /proc/net/tcp6 is four little-endian uint32 words (::1 ends in 01000000).
// Zero matches or two different uids fail closed.
func peerUIDFromProc(c net.Conn) (int, error) {
	local, err := procEndpoint(c.RemoteAddr())
	if err != nil {
		return 0, err
	}
	remote, err := procEndpoint(c.LocalAddr())
	if err != nil {
		return 0, err
	}
	path := procNetTCP
	if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok && tcp.IP.To4() == nil {
		path = procNetTCP6
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is /proc/net/tcp or a test snapshot
	if err != nil {
		return 0, fmt.Errorf("owner_only: read %s: %w", path, err)
	}
	return uidFromProc(b, local, remote)
}

func uidFromProc(data []byte, local, remote string) (int, error) {
	seen := false
	uid := 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || !strings.EqualFold(f[1], local) || !strings.EqualFold(f[2], remote) {
			continue
		}
		u, err := strconv.Atoi(f[7])
		if err != nil {
			return 0, fmt.Errorf("owner_only: peer uid field: %w", err)
		}
		if seen && u != uid {
			return 0, fmt.Errorf("owner_only: ambiguous peer uid for %s %s", local, remote)
		}
		seen = true
		uid = u
	}
	if !seen {
		return 0, fmt.Errorf("owner_only: peer uid not found for %s %s", local, remote)
	}
	return uid, nil
}

// procEndpoint formats addr the way /proc/net/tcp prints it.
func procEndpoint(addr net.Addr) (string, error) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil {
		return "", fmt.Errorf("owner_only: %v is not a TCP address", addr)
	}
	if v4 := tcp.IP.To4(); v4 != nil {
		return fmt.Sprintf("%02X%02X%02X%02X:%04X", v4[3], v4[2], v4[1], v4[0], tcp.Port), nil
	}
	v6 := tcp.IP.To16()
	if v6 == nil {
		return "", fmt.Errorf("owner_only: %v has no IP", addr)
	}
	var b strings.Builder
	b.Grow(37)
	for w := 0; w < 4; w++ {
		chunk := v6[w*4 : w*4+4]
		fmt.Fprintf(&b, "%02X%02X%02X%02X", chunk[3], chunk[2], chunk[1], chunk[0])
	}
	fmt.Fprintf(&b, ":%04X", tcp.Port)
	return b.String(), nil
}
