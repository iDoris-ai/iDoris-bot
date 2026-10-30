package enroll

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

// apiKeyWarnBefore is how close an API key expiry has to be before /readyz
// reports a warning. Exactly this far away is not a warning.
const apiKeyWarnBefore = 30 * 24 * time.Hour

// readyCacheTTL is how long a /readyz result, success or failure, is reused.
// readyMaxWaiters is how many requests may block on the single in-flight
// refresh. Further requests do not start another Headscale call.
const (
	readyCacheTTL   = 10 * time.Second
	readyMaxWaiters = 32
)

// ControlProbe is the expiry of the Headscale API key, when the server said.
type ControlProbe struct {
	ExpiresAt time.Time
	Known     bool
}

// ControlProber checks Headscale reachability and API-key validity with one
// cheap authenticated call. The enrollment service does not follow redirects
// on that call; the implementation lives on the Headscale client.
type ControlProber interface {
	ProbeControl(ctx context.Context) (ControlProbe, error)
}

// SetControlProber installs the readiness probe. A nil probe makes /readyz
// answer 503. /healthz does not use it.
func (s *Server) SetControlProber(p ControlProber) {
	s.mu.Lock()
	s.prober = p
	s.mu.Unlock()
}

func (s *Server) controlProber() ControlProber {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prober
}

type readyBody struct {
	Status          string     `json:"status"`
	Headscale       string     `json:"headscale"`
	APIKeyExpiresAt *time.Time `json:"api_key_expires_at,omitempty"`
	Warning         string     `json:"warning,omitempty"`
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	p := s.controlProber()
	if p == nil {
		writeJSON(w, http.StatusServiceUnavailable, readyBody{
			Status:    "unavailable",
			Headscale: "readiness probe is not configured",
		})
		return
	}
	body, code := s.cachedReady(p)
	writeJSON(w, code, body)
}

// cachedReady returns the cached probe when it is younger than readyCacheTTL.
// A stale or missing result starts one refresh; other callers wait for that
// refresh instead of calling Headscale again. Past readyMaxWaiters, a caller
// does not join the queue and does not start a probe.
func (s *Server) cachedReady(p ControlProber) (readyBody, int) {
	s.readyMu.Lock()
	now := s.now()
	if s.readyHave && now.Before(s.readyExp) {
		body, code := s.readyBody, s.readyCode
		s.readyMu.Unlock()
		return body, code
	}
	if s.readyFlight != nil {
		if s.readyWaiters >= readyMaxWaiters {
			body, code, have := s.readyBody, s.readyCode, s.readyHave
			s.readyMu.Unlock()
			if have {
				return body, code
			}
			return readyBody{Status: "unavailable", Headscale: "unreachable"}, http.StatusServiceUnavailable
		}
		ch := s.readyFlight
		s.readyWaiters++
		s.readyMu.Unlock()
		<-ch
		s.readyMu.Lock()
		s.readyWaiters--
		body, code, have := s.readyBody, s.readyCode, s.readyHave
		s.readyMu.Unlock()
		if !have {
			return readyBody{Status: "unavailable", Headscale: "unreachable"}, http.StatusServiceUnavailable
		}
		return body, code
	}
	ch := make(chan struct{})
	s.readyFlight = ch
	s.readyMu.Unlock()

	body, code := s.runReadyProbe(p)
	s.readyMu.Lock()
	s.readyBody = body
	s.readyCode = code
	s.readyHave = true
	s.readyExp = s.now().Add(readyCacheTTL)
	s.readyFlight = nil
	close(ch)
	s.readyMu.Unlock()
	return body, code
}

func (s *Server) runReadyProbe(p ControlProber) (readyBody, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe, err := p.ProbeControl(ctx)
	if err != nil {
		return readyBody{Status: "unavailable", Headscale: readyFailure(err)}, http.StatusServiceUnavailable
	}
	body := readyBody{Status: "ok", Headscale: "ok"}
	code := http.StatusOK
	if probe.Known && !probe.ExpiresAt.IsZero() {
		exp := probe.ExpiresAt.UTC()
		body.APIKeyExpiresAt = &exp
		switch {
		case !exp.After(s.now()):
			body.Status = "unavailable"
			body.Headscale = "api key expired"
			code = http.StatusServiceUnavailable
		case exp.Sub(s.now()) < apiKeyWarnBefore:
			body.Status = "warning"
			body.Warning = "api key expires in less than 30 days"
		}
	}
	return body, code
}

// readyFailure is a fixed phrase. Probe errors can carry upstream bodies, and
// those must not be copied onto an unauthenticated endpoint.
func readyFailure(err error) string {
	var ae *headscale.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "api key rejected"
		default:
			return fmt.Sprintf("headscale HTTP %d", ae.Status)
		}
	}
	return "unreachable"
}
