// idoris-vpnd keeps this machine enrolled in the iDoris Headscale control
// server. It is a long-running user daemon (launchd / systemd). In system
// mode it drives the official tailscaled via LocalAPI. In embedded mode it
// runs an in-process userspace Tailscale node and leaves the system client
// alone. auto picks one of those at startup.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
  idoris-vpnd join <code> [--yes] [--no-service] [--role-override ROLE] [--device IP] [--whole-subnet]
  idoris-vpnd gateway detect [--json]
  idoris-vpnd gateway setup [--yes] [--device IP] [--whole-subnet] [--no-service]
  idoris-vpnd gateway apply --plan FILE
  idoris-vpnd ui [--no-open]
  idoris-vpnd service install|uninstall [--config FILE]   manage the user service
  idoris-vpnd version

Config keys may also be given as IDORIS_VPN_* environment variables.
--mode auto (default) leaves a foreign system Tailscale alone and uses an
in-process node. --takeover switches that system Tailscale; the default is not to.

join accepts one code. A gateway code asks whether this machine is the Local AI
host. --yes skips prompts: a gateway then needs --device or --whole-subnet.
The program never escalates to root; it prints the sudo command instead.
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
	case "join":
		err = joinCmd(os.Args[2:], realDeps())
	case "gateway":
		err = gatewayCmd(os.Args[2:], realDeps())
	case "ui":
		err = uiCmd(os.Args[2:])
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
	fs.StringVar(&cfg.Mode, "mode", "", "auto|system|embedded (default auto)")
	fs.StringVar(&cfg.Role, "role", "", "member|local-ai|gateway|admin (default member; discovery wins when it returns a role)")
	fs.StringVar(&cfg.StateDir, "state-dir", "", "embedded node state directory (default ~/.idoris/vpn-state)")
	fs.StringVar(&cfg.StateFile, "state-file", "", "identity binding file (default ~/.idoris/vpnd-state.json)")
	fs.StringVar(&cfg.SOCKS5Listen, "socks5-listen", "", "loopback SOCKS5 address into the tailnet")
}

// loadConfig merges file < env < flags. Flags only override when set.
func loadConfig(args []string, fs *flag.FlagSet) (*vpnd.Config, error) {
	var flagCfg vpnd.Config
	var configPath string
	var takeover bool
	var noTakeover bool
	var routes string
	var forwards forwardList
	bindCommon(fs, &flagCfg, &configPath)
	fs.BoolVar(&takeover, "takeover", false, "switch the system Tailscale off a foreign tailnet")
	fs.BoolVar(&noTakeover, "no-takeover", false, "never switch the system Tailscale off a foreign tailnet")
	fs.StringVar(&routes, "advertise-routes", "", "comma-separated CIDRs to advertise (system mode only)")
	fs.Var(&forwards, "forward", "loopback forward listen=target (repeatable)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if set := visited(fs); set["takeover"] && set["no-takeover"] {
		return nil, errors.New("choose only one of --takeover and --no-takeover")
	}
	cfg, err := vpnd.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	set := visited(fs)
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
	override("mode", &cfg.Mode, flagCfg.Mode)
	override("role", &cfg.Role, flagCfg.Role)
	override("state-dir", &cfg.StateDir, flagCfg.StateDir)
	override("state-file", &cfg.StateFile, flagCfg.StateFile)
	override("socks5-listen", &cfg.SOCKS5Listen, flagCfg.SOCKS5Listen)
	if set["enroll-allow-insecure"] {
		cfg.EnrollAllowInsecure = flagCfg.EnrollAllowInsecure
	}
	if set["accept-routes"] {
		cfg.AcceptRoutes = flagCfg.AcceptRoutes
	}
	if set["takeover"] {
		cfg.Takeover = &takeover
	}
	if set["no-takeover"] {
		f := !noTakeover
		cfg.Takeover = &f
	}
	if set["advertise-routes"] {
		cfg.AdvertiseRoutes = splitCSV(routes)
	}
	if set["forward"] {
		cfg.Forwards = []vpnd.Forward(forwards)
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
	keys, controlURL, ident, binding, err := prepareKeys(cfg, log)
	if err != nil {
		return err
	}
	cfg.ControlURL = controlURL
	if ident.Role != "" {
		cfg.Role = ident.Role
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	node, err := openNode(ctx, cfg, controlURL, log)
	if err != nil {
		return err
	}
	defer func() { _ = node.Close() }()

	var routes []netip.Prefix
	if node.Mode == vpnd.ModeSystem {
		routes, err = cfg.RoutePrefixes()
		if err != nil {
			return err
		}
	}
	hostname := cfg.Hostname
	if node.Mode == vpnd.ModeEmbedded {
		hostname = node.Hostname
	}
	rec, err := vpnd.New(node.Backend, keys, vpnd.Options{
		ControlURL:         controlURL,
		Hostname:           hostname,
		AcceptRoutes:       cfg.AcceptRoutes,
		AcceptDNS:          cfg.AcceptDNSValue(),
		AdvertiseTags:      cfg.AdvertiseTags,
		AdvertiseRoutes:    routes,
		Takeover:           cfg.TakeoverValue(),
		LoginWhileStarting: node.LoginWhileStarting,
		Role:               cfg.Role,
		Identity:           ident,
		State:              binding,
		Interval:           cfg.IntervalDuration(),
	}, log)
	if err != nil {
		return err
	}

	access, err := vpnd.StartLocalAccess(node.Dialer, cfg.Forwards, cfg.SOCKS5Listen, log)
	if err != nil {
		return err
	}
	defer func() { _ = access.Close() }()

	ln, err := vpnd.Listen(cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	log.Info("idoris-vpnd starting", "version", version.Version, "mode", node.Mode, "mode_reason", node.Reason, "control_url", controlURL, "status_api", cfg.Listen, "os", runtime.GOOS)
	src := vpnd.View{Source: rec, Mode: node.Mode, ModeReason: node.Reason, Access: access}

	errc := make(chan error, 2)
	go func() { errc <- vpnd.ServeStatus(ctx, ln, vpnd.StatusHandler(src, version.Version)) }()
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

func prepareKeys(cfg *vpnd.Config, log *slog.Logger) (vpnd.KeySource, string, vpnd.Identity, *vpnd.StateFile, error) {
	controlURL := cfg.ControlURL
	var ident vpnd.Identity
	if cfg.EnrollURL == "" {
		binding, err := openBinding(cfg)
		if err != nil {
			return nil, "", ident, nil, err
		}
		if controlURL != "" && binding != nil {
			if err := binding.RememberControl(controlURL); err != nil {
				return nil, "", ident, nil, err
			}
		}
		return vpnd.StaticKey(cfg.AuthKey), controlURL, ident, binding, nil
	}
	ec := &enroll.Client{URL: cfg.EnrollURL, Token: cfg.EnrollToken, AllowInsecure: cfg.EnrollAllowInsecure}
	// Discover does not mint a key. It is the source of truth for tenant and role.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	d, err := ec.Discover(ctx)
	cancel()
	if err != nil {
		return nil, "", ident, nil, fmt.Errorf("discover control url via enrollment service: %w", err)
	}
	if controlURL != "" && !vpnd.SameControlURL(controlURL, d.ControlURL) {
		return nil, "", ident, nil, fmt.Errorf("enrollment service points at %s but config pins %s; refusing", d.ControlURL, controlURL)
	}
	if controlURL == "" {
		controlURL = d.ControlURL
	}
	role := strings.TrimSpace(d.Role)
	if role == "" {
		role = strings.TrimSpace(cfg.Role)
	}
	if cfg.Role != "" && d.Role != "" && cfg.Role != d.Role {
		log.Warn("config role differs from enrollment discovery; using discovery", "config_role", cfg.Role, "discovery_role", d.Role)
	}
	ident = vpnd.Identity{
		Tenant:           d.Tenant,
		Role:             role,
		TokenFingerprint: vpnd.TokenFingerprint(cfg.EnrollToken),
		Known:            true,
	}
	log.Info("control url discovered", "tenant", d.Tenant, "role", role, "control_url", controlURL)
	binding, err := openBinding(cfg)
	if err != nil {
		return nil, "", ident, nil, err
	}
	if err := binding.RememberControl(controlURL); err != nil {
		return nil, "", ident, nil, err
	}
	return &enrollKeys{c: ec, cfg: cfg, log: log}, controlURL, ident, binding, nil
}

func openBinding(cfg *vpnd.Config) (*vpnd.StateFile, error) {
	path := cfg.StateFile
	if path == "" {
		var err error
		path, err = vpnd.DefaultStateFile()
		if err != nil {
			return nil, err
		}
	}
	return vpnd.OpenState(path)
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
	fmt.Print(vpnd.FormatStatus(st))
	return nil
}

func visited(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// forwardList is the repeatable --forward listen=target flag.
type forwardList []vpnd.Forward

func (f *forwardList) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	parts := make([]string, len(*f))
	for i, fw := range *f {
		parts[i] = fw.Listen + "=" + fw.Target
	}
	return strings.Join(parts, ",")
}

func (f *forwardList) Set(s string) error {
	i := strings.IndexByte(s, '=')
	if i <= 0 || i == len(s)-1 {
		return fmt.Errorf("--forward %q: want listen=target", s)
	}
	*f = append(*f, vpnd.Forward{Listen: s[:i], Target: s[i+1:]})
	return nil
}

// runningNode is the Tailscale backend chosen at startup, plus the dialer
// local forwards use. System mode dials with the kernel; embedded mode dials
// through tsnet so MagicDNS names resolve without a TUN device.
type runningNode struct {
	Mode               string
	Reason             string
	Backend            vpnd.Backend
	Dialer             vpnd.Dialer
	Hostname           string
	LoginWhileStarting bool
	close              func() error
}

func (n *runningNode) Close() error {
	if n == nil || n.close == nil {
		return nil
	}
	return n.close()
}

// openNode decides system vs embedded once, then opens that backend.
// The probe is read-only and only runs for auto. advertise_routes is rejected
// again after auto resolves, before an embedded node is started.
func openNode(ctx context.Context, cfg *vpnd.Config, controlURL string, log *slog.Logger) (*runningNode, error) {
	req := cfg.Mode
	if req == "" {
		req = vpnd.ModeAuto
	}
	var view vpnd.SystemView
	if req == vpnd.ModeAuto {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		view = vpnd.ProbeSystem(probeCtx, vpnd.NewLocalBackend(cfg.TailscaleSocket), controlURL)
		cancel()
	}
	d, err := vpnd.DecideMode(req, cfg.TakeoverValue(), view, controlURL)
	if err != nil {
		return nil, err
	}
	log.Info("vpn mode", "mode", d.Mode, "reason", d.Reason)
	if err := cfg.RejectEmbeddedRoutes(d.Mode); err != nil {
		return nil, err
	}
	if d.Mode == vpnd.ModeEmbedded {
		dir := cfg.StateDir
		if dir == "" {
			dir, err = vpnd.DefaultStateDir()
			if err != nil {
				return nil, err
			}
		}
		emb, err := vpnd.StartEmbedded(vpnd.EmbeddedOptions{
			StateDir:      dir,
			Hostname:      cfg.Hostname,
			ControlURL:    controlURL,
			AdvertiseTags: cfg.AdvertiseTags,
		}, log)
		if err != nil {
			return nil, err
		}
		return &runningNode{
			Mode:               d.Mode,
			Reason:             d.Reason,
			Backend:            emb.Backend(),
			Dialer:             emb,
			Hostname:           emb.Hostname(),
			LoginWhileStarting: emb.Fresh(),
			close:              emb.Close,
		}, nil
	}
	return &runningNode{
		Mode:     vpnd.ModeSystem,
		Reason:   d.Reason,
		Backend:  vpnd.NewLocalBackend(cfg.TailscaleSocket),
		Dialer:   &net.Dialer{},
		Hostname: cfg.Hostname,
		close:    func() error { return nil },
	}, nil
}
