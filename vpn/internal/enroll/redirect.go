package enroll

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrRedirect is wrapped when an authenticated call receives a 3xx.
// The Location value is in the error text. The bearer token was not sent
// to that URL.
var ErrRedirect = errors.New("refusing redirect")

// httpClient returns a client that never follows redirects. A caller-supplied
// client is copied so its CheckRedirect is not mutated; its Transport is kept
// so tests can trust an httptest certificate.
func (c *Client) httpClient() *http.Client {
	hc := &http.Client{Timeout: 20 * time.Second}
	if c.HTTP != nil {
		cp := *c.HTTP
		hc = &cp
		if hc.Timeout == 0 {
			hc.Timeout = 20 * time.Second
		}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return hc
}

func errRefusingRedirect(resp *http.Response) error {
	loc := ""
	code := 0
	if resp != nil {
		code = resp.StatusCode
		loc = strings.TrimSpace(resp.Header.Get("Location"))
	}
	if loc == "" {
		return fmt.Errorf("%w: HTTP %d with no Location", ErrRedirect, code)
	}
	return fmt.Errorf("%w to %q", ErrRedirect, loc)
}
