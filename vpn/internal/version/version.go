// Package version holds build metadata injected via -ldflags.
package version

// Version is set at build time: -ldflags "-X .../internal/version.Version=v0.1.0".
var Version = "dev"
