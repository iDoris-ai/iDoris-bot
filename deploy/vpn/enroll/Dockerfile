# syntax=docker/dockerfile:1
#
# idoris-vpn-enroll: static Go binary in a minimal image.
# Build context is ../../vpn (see compose.yaml); this file lives next to the
# deployment so the vpn/ module stays free of deployment files.
#
# GO_VERSION must be >= the `go` line in vpn/go.mod, otherwise the toolchain is
# downloaded on every build.

ARG GO_VERSION=1.27.3
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
      -ldflags "-s -w -X github.com/iDoris-ai/iDoris-bridge/vpn/internal/version.Version=${VERSION}" \
      -o /out/idoris-vpn-enroll ./cmd/idoris-vpn-enroll

FROM alpine:${ALPINE_VERSION}
# alpine ships ca-certificates-bundle; busybox wget is used by the healthcheck.
COPY --from=build /out/idoris-vpn-enroll /usr/local/bin/idoris-vpn-enroll
# Overridden by compose (`user:`) so the process can read 0600 secret files that
# bootstrap.sh wrote as the operator.
USER 65532:65532
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8787/healthz || exit 1
ENTRYPOINT ["idoris-vpn-enroll"]
CMD ["serve", "--config", "/etc/idoris/enroll.json", "--listen", "0.0.0.0:8787"]
