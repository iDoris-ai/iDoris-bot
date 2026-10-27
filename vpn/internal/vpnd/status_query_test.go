package vpnd

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestR2GQueryStatusClosesConnections(t *testing.T) {
	var mu sync.Mutex
	opened, closed := 0, 0
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"phase":"connected"}`))
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			mu.Lock()
			defer mu.Unlock()
			switch state {
			case http.StateNew:
				opened++
			case http.StateClosed:
				closed++
			}
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	spec := "tcp:" + ln.Addr().String()
	const n = 30
	for range n {
		out, err := QueryStatus(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if out["phase"] != "connected" {
			t.Fatalf("status %#v", out)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		gotOpen, gotClosed := opened, closed
		mu.Unlock()
		if gotOpen >= n && gotClosed >= gotOpen {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("connections stayed open: opened %d closed %d", opened, closed)
}
