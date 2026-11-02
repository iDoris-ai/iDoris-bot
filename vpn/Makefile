GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/iDoris-ai/iDoris-bridge/vpn/internal/version.Version=$(VERSION)

.PHONY: build test lint integration integration-lan integration-wizard lint-integration build-linux clean

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

# Join-code gateway wizard. Own compose project (idoris-vpn-wizard-*).
integration-wizard:
	cd integration && $(GO) test -tags integration -count=1 -v -timeout 20m -run 'TestWizardGatewayJoin' ./...

lint-integration:
	golangci-lint run --build-tags integration ./...

# Third-party license gate for the binaries under ./cmd (not tests).
#
# Allowlist, enforced by scripts/licenses.go (allowedLicenses):
#   Apache-2.0, BSD-2-Clause, BSD-3-Clause, MIT, ISC
#
# Extending that list is a legal decision and needs a human review.
# Read the new license text, decide it can be redistributed inside this
# Apache-2.0 product, then add the SPDX name in scripts/licenses.go.
# Do not add GPL, AGPL, LGPL, MPL, CC, or Unknown to make the check pass.
# After any allowlist change, run `make notices` and commit
# THIRD_PARTY_NOTICES.md in the same change.
#
# The scanner is `go run github.com/google/go-licenses@v1.6.0`.
# `go run` builds that binary for the host. A wrapper then sets GOOS,
# because putting GOOS on `go run` itself produces a binary that will
# not start (exec format error).
#
# `make licenses` checks linux, darwin, and windows (amd64 and arm64,
# CGO_ENABLED=0) and fails if THIRD_PARTY_NOTICES.md is stale.
# VPN_LICENSES_PROBE_DIR points at an extra module to check with the same
# allowlist. It cannot drop a package or add an allowed license.

.PHONY: licenses notices

licenses:
	GO="$(GO)" $(GO) run -tags vpnlicenses ./scripts/licenses.go check

notices:
	GO="$(GO)" $(GO) run -tags vpnlicenses ./scripts/licenses.go notices
