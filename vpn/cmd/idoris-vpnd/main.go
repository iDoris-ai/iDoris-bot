// idoris-vpnd keeps the official Tailscale client of this machine enrolled in
// the iDoris Headscale control server. It is a long-running user daemon
// (launchd / systemd) that drives tailscaled via LocalAPI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/version"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func usage() {
	fmt.Fprintf(os.Stderr, `idoris-vpnd %s — iDoris VPN membership daemon

Usage:
  idoris-vpnd run     [--config FILE] [flags]   run in the foreground (launchd/systemd)
  idoris-vpnd status  [--listen SPEC] [--json]  query a running daemon
  idoris-vpnd service install|uninstall [--config FILE]   manage the user service
  idoris-vpnd version

Config keys may also be given as IDORIS_VPN_* environment variables.
`, version.Version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "status":
		err = statusCmd(os.Args[2:])
	case "service":
		err = serviceCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "idoris-vpnd:", err)
		os.Exit(1)
	}
}

func bindCommon(fs *flag.FlagSet, cfg *vpnd.Config, configPath *string) {
	fs.StringVar(configPath, "config", "", "JSON config file")
	fs.StringVar(&cfg.ControlURL, "control-url", "", "iDoris Headscale URL (e.g. https://vpn.example.org)")
	fs.StringVar(&cfg.EnrollURL, "enroll-url", "", "iDoris enrollment service URL")
	fs.StringVar(&cfg.EnrollToken, "enroll-token", "", "tenant enrollment token (prefer --enroll-token-file)")
	fs.StringVar(&cfg.EnrollTokenFile, "enroll-token-file", "", "file containing the enrollment token")
	fs.BoolVar(&cfg.EnrollAllowInsecure, "enroll-allow-insecure", false, "allow http:// enrollment URL (labs only)")
	fs.StringVar(&cfg.AuthKey, "auth-key", "", "static Headscale pre-auth key (labs only)")
	fs.StringVar(&cfg.AuthKeyFile, "auth-key-file", "", "file containing a static pre-auth key")
	fs.StringVar(&cfg.Hostname, "hostname", "", "node hostname to request")
	fs.BoolVar(&cfg.AcceptRoutes, "accept-routes", false, "accept subnet routes advertised in the tailnet")
	fs.StringVar(&cfg.TailscaleSocket, "tailscale-socket", "", "tailscaled LocalAPI socket override")
	fs.StringVar(&cfg.Listen, "listen", "", "status API: unix:<path> or tcp:127.0.0.1:<port>")
	fs.StringVar(&cfg.Interval, "interval", "", "healthy reconcile interval (default 5s)")
	fs.StringVar(&cfg.LogLevel, "log-level", "", "debug|info|warn|error")
}

// loadConfig merges file < env < flags. Flags only override when set.
func loadConfig(args []string, fs *flag.FlagSet) (*vpnd.Config, error) {
	var flagCfg vpnd.Config
	var configPath string
	var noTakeover bool
	bindCommon(fs, &flagCfg, &configPath)
	fs.BoolVar(&noTakeover, "no-takeover", false, "never switch away from a running foreign tailnet")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg, err := vpnd.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	override := func(name string, dst *string, v string) {
		if set[name] {
			*dst = v
		}
	}
	override("control-url", &cfg.ControlURL, flagCfg.ControlURL)
	override("enroll-url", &cfg.EnrollURL, flagCfg.EnrollURL)
	override("enroll-token", &cfg.EnrollToken, flagCfg.EnrollToken)
	override("enroll-token-file", &cfg.EnrollTokenFile, flagCfg.EnrollTokenFile)
	override("auth-key", &cfg.AuthKey, flagCfg.AuthKey)
	override("auth-key-file", &cfg.AuthKeyFile, flagCfg.AuthKeyFile)
	override("hostname", &cfg.Hostname, flagCfg.Hostname)
	override("tailscale-socket", &cfg.TailscaleSocket, flagCfg.TailscaleSocket)
	override("listen", &cfg.Listen, flagCfg.Listen)
	override("interval", &cfg.Interval, flagCfg.Interval)
	override("log-level", &cfg.LogLevel, flagCfg.LogLevel)
	if set["enroll-allow-insecure"] {
		cfg.EnrollAllowInsecure = flagCfg.EnrollAllowInsecure
	}
	if set["accept-routes"] {
		cfg.AcceptRoutes = flagCfg.AcceptRoutes
	}
	if set["no-takeover"] {
		f := !noTakeover
		cfg.Takeover = &f
	}
	if err := cfg.Resolve(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

// enrollKeys adapts the enrollment client to vpnd.KeySource and learns the
// control URL from the service when the config leaves it empty.
type enrollKeys struct {
	c   *enroll.Client
	cfg *vpnd.Config
	log *slog.Logger
}

// enrollHostname is the hostname reported to the enrollment service: the
// configured one, else the OS hostname.
func enrollHostname(configured string) string {
	if configured != "" {
		return configured
	}
	host, _ := os.Hostname()
	return host
}

func (e *enrollKeys) AuthKey(ctx context.Context) (string, error) {
	host := enrollHostname(e.cfg.Hostname)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := e.c.Fetch(ctx, enroll.Request{Hostname: host, OS: runtime.GOOS, DaemonVersion: version.Version})
	if err != nil {
		return "", err
	}
	if e.cfg.ControlURL != "" && !vpnd.SameControlURL(e.cfg.ControlURL, resp.ControlURL) {
		return "", fmt.Errorf("enrollment service points at %s but config pins %s; refusing", resp.ControlURL, e.cfg.ControlURL)
	}
	e.log.Info("enrollment key issued", "tenant", resp.Tenant, "expires_at", resp.ExpiresAt.Format(time.RFC3339))
	return resp.AuthKey, nil
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig(args, fs)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	var keys vpnd.KeySource
	controlURL := cfg.ControlURL
	if cfg.EnrollURL != "" {
		ec := &enroll.Client{URL: cfg.EnrollURL, Token: cfg.EnrollToken, AllowInsecure: cfg.EnrollAllowInsecure}
		if controlURL == "" {
			// Learn the control URL up front so the reconciler can compare prefs.
			// Discover does not mint a key, so restarting an enrolled daemon is free.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			d, err := ec.Discover(ctx)
			cancel()
			if err != nil {
				return fmt.Errorf("discover control url via enrollment service: %w", err)
			}
			controlURL = d.ControlURL
			cfg.ControlURL = controlURL
			log.Info("control url discovered", "tenant", d.Tenant, "control_url", controlURL)
		}
		keys = &enrollKeys{c: ec, cfg: cfg, log: log}
	} else {
		keys = vpnd.StaticKey(cfg.AuthKey)
	}

	be := vpnd.NewLocalBackend(cfg.TailscaleSocket)
	rec, err := vpnd.New(be, keys, vpnd.Options{
		ControlURL:    controlURL,
		Hostname:      cfg.Hostname,
		AcceptRoutes:  cfg.AcceptRoutes,
		AcceptDNS:     cfg.AcceptDNSValue(),
		AdvertiseTags: cfg.AdvertiseTags,
		Takeover:      cfg.TakeoverValue(),
		Interval:      cfg.IntervalDuration(),
	}, log)
	if err != nil {
		return err
	}

	ln, err := vpnd.Listen(cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("idoris-vpnd starting", "version", version.Version, "control_url", controlURL, "status_api", cfg.Listen, "os", runtime.GOOS)

	errc := make(chan error, 2)
	go func() { errc <- vpnd.ServeStatus(ctx, ln, vpnd.StatusHandler(rec, version.Version)) }()
	go func() { errc <- rec.Run(ctx) }()
	select {
	case <-ctx.Done():
		log.Info("idoris-vpnd stopping")
		return nil
	case err := <-errc:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	listen := fs.String("listen", vpnd.DefaultListen(), "status API address of the daemon")
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := vpnd.QueryStatus(ctx, *listen)
	if err != nil {
		return fmt.Errorf("daemon not reachable at %s: %w", *listen, err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	fmt.Printf("phase:        %v\n", st["phase"])
	fmt.Printf("control_url:  %v\n", st["control_url"])
	fmt.Printf("backend:      %v\n", st["backend_state"])
	if ips, ok := st["tailnet_ips"].([]any); ok && len(ips) > 0 {
		fmt.Printf("tailnet_ips:  %v\n", ips)
	}
	if v, ok := st["self_dns_name"]; ok && v != "" {
		fmt.Printf("self:         %v\n", v)
	}
	if v, ok := st["last_error"]; ok && v != "" {
		fmt.Printf("last_error:   %v\n", v)
	}
	fmt.Printf("attempts:     %v\n", st["login_attempts"])
	fmt.Printf("daemon:       %v\n", st["daemon_version"])
	return nil
}
