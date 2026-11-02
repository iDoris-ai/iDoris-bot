# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# tag: docker/dockerfile:1
#
# idoris-vpn-enroll: static Go binary in a minimal image.
# Build context is ../../vpn (see compose.yaml); this file lives next to the
# deployment so the vpn/ module stays free of deployment files.
#
# The Go image tag must be >= the `go` line in vpn/go.mod, otherwise the
# toolchain is downloaded on every build. Digests are the multi-arch index.
# golang:1.27.3-alpine is itself Alpine 3.24; the runtime stage stays 3.23.
# To move a pin: look up the index digest, keep the tag in the name, then
# `docker compose pull` and rebuild. See docs/14-VPN-OPERATIONS.md.

ARG GO_IMAGE=golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb
ARG RUNTIME_IMAGE=alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

FROM ${GO_IMAGE} AS build
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

FROM ${RUNTIME_IMAGE}
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
