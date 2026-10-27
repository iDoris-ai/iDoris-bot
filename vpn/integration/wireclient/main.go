// Command wireclient is the hand-written SOCKS5 client for the wire integration
// test (RFC 1928 CONNECT and RFC 1929 username/password). It has no third-party
// dependencies. Passwords are never written to stdout or stderr.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	start := time.Now()
	var err error
	switch os.Args[1] {
	case "none":
		err = expectReject(os.Args[2:], "", "")
	case "wrong":
		err = expectReject(os.Args[2:], "wrong", "wrong")
	case "auth":
		err = echoAuth(os.Args[2:])
	case "hold":
		err = hold(os.Args[2:])
	default:
		usage()
	}
	fmt.Printf("elapsed_ms %d\n", time.Since(start).Milliseconds())
	if err != nil {
		fmt.Fprintln(os.Stderr, "wireclient:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wireclient none|wrong|auth|hold ...")
	os.Exit(2)
}

func expectReject(args []string, user, pass string) error {
	if len(args) != 2 {
		usage()
	}
	c, err := socksConnect(args[0], args[1], user, pass)
	if c != nil {
		_ = c.Close()
	}
	if errors.Is(err, errRejected) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		fmt.Println("rejected")
		return nil
	}
	if err == nil {
		return errors.New("server accepted credentials that must be rejected")
	}
	return err
}

func echoAuth(args []string) error {
	if len(args) != 4 {
		usage()
	}
	n, err := strconv.Atoi(args[3])
	if err != nil {
		return err
	}
	user, pass, err := readAuth(args[2])
	if err != nil {
		return err
	}
	c, err := socksConnect(args[0], args[1], user, pass)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return echo(c, n)
}

func hold(args []string) error {
	if len(args) != 4 {
		usage()
	}
	user, pass, err := readAuth(args[2])
	if err != nil {
		return err
	}
	c, err := socksConnect(args[0], args[1], user, pass)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := os.WriteFile(args[3], []byte("up\n"), 0o644); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, c)
	return err
}

func readAuth(path string) (string, string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path is the daemon's 0600 socks5.auth inside the fixture
	if err != nil {
		return "", "", err
	}
	line := strings.TrimRight(string(b), "\r\n")
	user, pass, ok := strings.Cut(line, ":")
	if !ok || user == "" || pass == "" {
		return "", "", errors.New("auth file must contain user:password")
	}
	return user, pass, nil
}

var errRejected = errors.New("rejected")

func socksConnect(proxy, target, user, pass string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second) //nolint:gosec // G704: proxy is the fixture's loopback SOCKS5
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	method := byte(0x00)
	if user != "" || pass != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, 0x01, method}); err != nil {
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != method {
		return nil, errRejected
	}
	if method == 0x02 {
		if err := writeAuth(c, user, pass); err != nil {
			return nil, err
		}
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || len(host) == 0 || len(host) > 255 {
		return nil, errors.New("bad target")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[1] != 0x00 {
		return nil, errRejected
	}
	if err := discardBind(c, hdr[3]); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

func writeAuth(c net.Conn, user, pass string) error {
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := c.Write(buf); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return err
	}
	if rep[1] != 0x00 {
		return errRejected
	}
	return nil
}

func discardBind(c net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return err
		}
		n = int(ln[0])
	default:
		return errors.New("bad bind address")
	}
	if n > 0 {
		if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
			return err
		}
	}
	_, err := io.ReadFull(c, make([]byte, 2))
	return err
}

func echo(c net.Conn, n int) error {
	if n < 0 || n > 1<<20 {
		return errors.New("nbytes out of range")
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	body := make([]byte, n)
	for i := range body {
		body[i] = byte(i)
	}
	if err := binary.Write(c, binary.BigEndian, uint32(n)); err != nil {
		return err
	}
	if _, err := c.Write(body); err != nil {
		return err
	}
	var gotN uint32
	if err := binary.Read(c, binary.BigEndian, &gotN); err != nil {
		return err
	}
	if gotN != uint32(n) {
		return fmt.Errorf("length %d, want %d", gotN, n)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	for i := range got {
		if got[i] != body[i] {
			return fmt.Errorf("byte %d mismatch", i)
		}
	}
	fmt.Printf("echoed %d bytes\n", n)
	return nil
}
