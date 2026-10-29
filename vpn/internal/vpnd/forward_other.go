//go:build !unix

package vpnd

import (
	"context"
	"net"
)

func isTemporaryAccept(error) bool { return false }

// watchDisconnect is a no-op off Unix. The dial still stops when the daemon
// context is cancelled or the dial deadline passes.
func watchDisconnect(net.Conn, context.CancelFunc) func() { return func() {} }
