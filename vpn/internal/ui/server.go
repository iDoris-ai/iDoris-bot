// Package ui serves the local onboarding page.
//
// The server binds 127.0.0.1 on a random port. The printed URL carries a
// one-time secret. After that, the secret must arrive as the idoris_ui cookie
// or the X-Idoris-UI-Secret header. State-changing requests also need a
// same-origin signal and the CSRF token from the page. Nothing on the page
// is loaded from another host.
package ui

import (
	"os"
	"strconv"
	"strings"
)

// CurrentLoginUID reads Linux /proc/self/loginuid. An absent file, an unreadable
// file, or the unset value 4294967295 all mean "unknown" (-1).
func CurrentLoginUID() int {
	b, err := os.ReadFile("/proc/self/loginuid") //nolint:gosec // fixed kernel path, not a user path
	if err != nil {
		return -1
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "4294967295" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return int(n)
}
