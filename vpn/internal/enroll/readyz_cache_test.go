package enroll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type blockingProber struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	once    sync.Once
	probe   ControlProbe
	err     error
}

func (b *blockingProber) ProbeControl(context.Context) (ControlProbe, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.once.Do(func() { close(b.started) })
	<-b.release
	if b.err != nil {
		return ControlProbe{}, b.err
	}
	return b.probe, nil
}

func (b *blockingProber) n() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func TestR2GReadyzSingleFlight(t *testing.T) {
	p := &blockingProber{
		started: make(chan struct{}),
		release: make(chan struct{}),
		probe:   ControlProbe{Known: true, ExpiresAt: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
	}
	s := readyServer(t, p)
	const extra = 4
	n := 1 + readyMaxWaiters + extra
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			codes[i] = rr.Code
		}(i)
	}
	select {
	case <-p.started:
	case <-time.After(2 * time.Second):
		t.Fatal("readyz did not probe")
	}
	time.Sleep(50 * time.Millisecond)
	if got := p.n(); got != 1 {
		t.Fatalf("upstream probes during one TTL %d", got)
	}
	close(p.release)
	wg.Wait()
	ok, unavailable := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusServiceUnavailable:
			unavailable++
		default:
			t.Fatalf("status %d", c)
		}
	}
	if ok != 1+readyMaxWaiters || unavailable != extra {
		t.Fatalf("ok %d unavailable %d", ok, unavailable)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK || p.n() != 1 {
		t.Fatalf("cached status %d probes %d", rr.Code, p.n())
	}
	base := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base.Add(readyCacheTTL) }
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK || p.n() != 2 {
		t.Fatalf("after ttl status %d probes %d", rr.Code, p.n())
	}
}

func TestR2GReadyzCachesFailure(t *testing.T) {
	p := &fakeProber{err: errors.New("dial down")}
	s := readyServer(t, p)
	for range 5 {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusServiceUnavailable || !bytesContains(rr.Body.String(), "unreachable") {
			t.Fatalf("body %d %s", rr.Code, rr.Body.String())
		}
	}
	if p.calls != 1 {
		t.Fatalf("failure probes %d", p.calls)
	}
}

func bytesContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || containsString(s, sub))
}

func containsString(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
