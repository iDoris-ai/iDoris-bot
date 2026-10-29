package vpnd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// tailscale.com/net/socks5.Server does speak RFC 1929 (its Username and
// Password fields). Server.Serve is still the wrong shape here: it owns
// Accept, dials with context.Background and a fixed 5 second timeout, does
// not bound connections, and treats the first Accept error as shutdown.
// None of that can carry the per-listener cap, the dial deadline, client
// cancel, the gate, or a failed listener state. This file is CONNECT plus
// optional username/password, and nothing else.

const socksHandshakeTimeout = 10 * time.Second

func (a *LocalAccess) serveSOCKS(client net.Conn) {
	defer func() { _ = client.Close() }()
	if !a.track(client) {
		return
	}
	defer a.untrack(client)
	_ = client.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	target, err := a.socksHandshake(client)
	_ = client.SetDeadline(time.Time{})
	if err != nil {
		a.log.Debug("socks5 handshake failed", "err", err)
		return
	}
	if !a.gateOpen() {
		socksReply(client, 0x02)
		return
	}
	upstream, err := a.dialUpstream(client, target)
	if err != nil {
		a.log.Debug("socks5 dial failed", "target", target, "err", err)
		socksReply(client, 0x05)
		return
	}
	defer func() { _ = upstream.Close() }()
	if !a.track(upstream) {
		return
	}
	defer a.untrack(upstream)
	socksReply(client, 0x00)
	done := make(chan struct{})
	go func() {
		copyHalf(upstream, client)
		close(done)
	}()
	copyHalf(client, upstream)
	<-done
}

func (a *LocalAccess) socksHandshake(client net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("socks version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return "", err
	}
	needAuth := a.user != ""
	method := byte(0xff)
	want := byte(0x00)
	if needAuth {
		want = 0x02
	}
	for _, m := range methods {
		if m == want {
			method = want
			break
		}
	}
	if _, err := client.Write([]byte{0x05, method}); err != nil {
		return "", err
	}
	if method == 0xff {
		return "", errors.New("socks5: no acceptable method")
	}
	if needAuth {
		if err := a.socksAuth(client); err != nil {
			return "", err
		}
	}
	return socksTarget(client)
}

func (a *LocalAccess) socksAuth(client net.Conn) error {
	ver := make([]byte, 1)
	if _, err := io.ReadFull(client, ver); err != nil {
		return err
	}
	if ver[0] != 0x01 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks5 auth version %d", ver[0])
	}
	ulen := make([]byte, 1)
	if _, err := io.ReadFull(client, ulen); err != nil {
		return err
	}
	user := make([]byte, int(ulen[0]))
	if _, err := io.ReadFull(client, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(client, plen); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(client, pass); err != nil {
		return err
	}
	if !credEqual(string(user), string(pass), a.user, a.pass) {
		_, _ = client.Write([]byte{0x01, 0x01})
		return errors.New("socks5: authentication failed")
	}
	_, err := client.Write([]byte{0x01, 0x00})
	return err
}

func socksTarget(client net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("socks version %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		socksReply(client, 0x07)
		return "", fmt.Errorf("socks5: command %d is not CONNECT", hdr[1])
	}
	var host string
	switch hdr[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(client, n); err != nil {
			return "", err
		}
		if n[0] == 0 {
			socksReply(client, 0x08)
			return "", errors.New("socks5: empty domain")
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		socksReply(client, 0x08)
		return "", fmt.Errorf("socks5: address type %d", hdr[3])
	}
	var portb [2]byte
	if _, err := io.ReadFull(client, portb[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portb[:])
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func socksReply(w io.Writer, rep byte) {
	_, _ = w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func init() {
	_ = (*LocalAccess).serveSOCKS
	_ = socksHandshakeTimeout
}
