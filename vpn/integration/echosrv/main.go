// Command echosrv is the TCP peer used by the embedded-mode integration test.
// A length-prefixed frame (uint32 big-endian, then that many bytes) is echoed
// back, so the check does not depend on TCP half-close.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxFrame = 1 << 21 // 2 MiB

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: echosrv listen ADDR | echosrv dial ADDR NBYTES")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "listen":
		err = listen(os.Args[2])
	case "dial":
		n, convErr := strconv.Atoi(os.Args[3])
		if convErr != nil {
			err = convErr
			break
		}
		err = dial(os.Args[2], n)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "echosrv:", err)
		os.Exit(1)
	}
}

func listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Println("listening", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = c.Close() }()
			if err := serve(c); err != nil {
				fmt.Println("serve:", err)
			}
		}()
	}
}

func serve(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	var n uint32
	if err := binary.Read(c, binary.BigEndian, &n); err != nil {
		return err
	}
	if n > maxFrame {
		return fmt.Errorf("frame %d exceeds %d", n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if err := binary.Write(c, binary.BigEndian, n); err != nil {
		return err
	}
	_, err := c.Write(buf)
	return err
}

func dial(addr string, n int) error {
	if n < 0 || n > maxFrame {
		return fmt.Errorf("nbytes %d out of range", n)
	}
	network := "tcp"
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		network = "unix"
		addr = path
	}
	c, err := net.DialTimeout(network, addr, 20*time.Second) //nolint:gosec // G704: addr is the fixture target supplied by the integration test
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
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
			return fmt.Errorf("byte %d = %d, want %d", i, got[i], body[i])
		}
	}
	fmt.Printf("echoed %d bytes\n", n)
	return nil
}
