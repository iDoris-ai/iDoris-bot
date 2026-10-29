//go:build unix

package vpnd

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

func isTemporaryAccept(err error) bool {
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR)
}

// watchDisconnect cancels the dial when the client connection closes.
// The duplicated fd is peeked so the real connection's read buffer is left
// alone. stop closes that fd and waits for the goroutine, which is what keeps
// a finished dial from leaking the watch.
func watchDisconnect(c net.Conn, cancel context.CancelFunc) (stop func()) {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return func() {}
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return func() {}
	}
	var dupfd int
	var dupErr error
	if err := raw.Control(func(fd uintptr) {
		dupfd, dupErr = syscall.Dup(int(fd))
	}); err != nil || dupErr != nil {
		return func() {}
	}
	if err := syscall.SetNonblock(dupfd, true); err != nil {
		_ = syscall.Close(dupfd)
		return func() {}
	}
	done := make(chan struct{})
	stopCh := make(chan struct{})
	go func() {
		defer close(done)
		var buf [1]byte
		// syscall.Poll is not in the Darwin syscall package. A short ticker
		// is the same 200ms budget: peek, and otherwise wait until the peer
		// hangs up or stop closes the duplicated fd.
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			closed, halt := peerClosed(dupfd, buf[:])
			if halt {
				return
			}
			if closed {
				cancel()
				return
			}
			select {
			case <-stopCh:
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopCh)
			_ = syscall.Close(dupfd)
			<-done
		})
	}
}

// peerClosed reports whether the peer has hung up. halt means the duplicated
// fd was closed by stop and the watch must exit without treating that as a
// client disconnect. EBADF is that case. A readable byte is not a disconnect:
// MSG_PEEK leaves it for the real connection.
func peerClosed(fd int, buf []byte) (closed, halt bool) {
	n, _, err := syscall.Recvfrom(fd, buf, syscall.MSG_PEEK)
	switch {
	case err == nil && n == 0:
		return true, false
	case err == nil:
		return false, false
	case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK):
		return false, false
	case errors.Is(err, syscall.EBADF):
		return false, true
	default:
		return true, false
	}
}
