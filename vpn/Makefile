GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/iDoris-ai/iDoris-bridge/vpn/internal/version.Version=$(VERSION)

.PHONY: build test lint integration build-linux clean

build:
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/idoris-vpnd ./cmd/idoris-vpnd
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/idoris-vpn-enroll ./cmd/idoris-vpn-enroll

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(or $(ARCH),$(shell $(GO) env GOARCH)) $(GO) build -ldflags '$(LDFLAGS)' -o bin/idoris-vpnd-linux ./cmd/idoris-vpnd

test:
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

# Real Headscale + real tailscaled in Docker (~2 min).
integration:
	cd integration && $(GO) test -tags integration -count=1 -v -timeout 10m ./...

clean:
	rm -rf bin

# LAN direct path, away-from-LAN DERP, and subnet-router gateway.
# Own compose project inside the test (idoris-vpn-lan-*). See docs/15.
integration-lan:
	cd integration && $(GO) test -tags integration -count=1 -v -timeout 20m -run 'TestLanDirect|TestLanAwayRelay|TestGatewaySubnetRoute' ./...

lint-integration:
	golangci-lint run --build-tags integration ./...
