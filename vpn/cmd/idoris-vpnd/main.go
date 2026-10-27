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
in-process node. local-ai and gateway never use that fallback: they wait until
the official tailscaled is reachable. --takeover switches the system Tailscale;
the default is not to.

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
	var sshFlag string
	var dnsFlag string
	var tags string
	var forwards forwardList
	bindCommon(fs, &flagCfg, &configPath)
	fs.BoolVar(&takeover, "takeover", false, "switch the system Tailscale off a foreign tailnet")
	fs.BoolVar(&noTakeover, "no-takeover", false, "never switch the system Tailscale off a foreign tailnet")
	fs.StringVar(&routes, "advertise-routes", "", "comma-separated CIDRs to advertise (system mode only)")
	fs.StringVar(&sshFlag, "ssh", "", "true or false Tailscale SSH; omit to leave RunSSH unmanaged")
	fs.StringVar(&dnsFlag, "accept-dns", "", "true or false; omit to accept DNS (the default)")
	fs.StringVar(&tags, "advertise-tags", "", "comma-separated tags to record; not sent at login (Headscale tags the pre-auth key)")
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
	if set["ssh"] {
		b, err := vpnd.ParseBool(sshFlag)
		if err != nil {
			return nil, fmt.Errorf("--ssh: %w", err)
		}
		cfg.SSH = &b
	}
	if set["accept-dns"] {
		b, err := vpnd.ParseBool(dnsFlag)
		if err != nil {
			return nil, fmt.Errorf("--accept-dns: %w", err)
		}
		cfg.AcceptDNS = &b
	}
	if set["advertise-tags"] {
		cfg.AdvertiseTags = splitCSV(tags)
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
	keys, controlURL, ident, binding, enrollReachable, err := prepareKeys(cfg, log)
	if err != nil {
		return err
	}
	cfg.ControlURL = controlURL
	if ident.Role != "" {
		role := strings.ToLower(strings.TrimSpace(ident.Role))
		if !vpnd.ValidRole(role) {
			return fmt.Errorf("enrollment discovery role %q: want member, local-ai, gateway, or admin", ident.Role)
		}
		cfg.Role = role
	}
	if err := cfg.RejectEmbeddedRole(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := vpnd.Listen(cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	holder := &vpnd.StatusSwap{}
	errc := make(chan error, 2)
	go func() { errc <- vpnd.ServeStatus(ctx, ln, vpnd.StatusHandler(holder, version.Version)) }()

	node, err := openNode(ctx, cfg, controlURL, log, func(d vpnd.ModeDecision) {
		msg := vpnd.WaitingTailscaledMessage(cfg.Role)
		log.Warn(msg, "role", cfg.Role)
		warnings := []string{msg}
		if !enrollReachable {
			warnings = append(warnings, vpnd.EnrollUnreachableWarning)
		}
		holder.Store(vpnd.FixedSnapshot(vpnd.Snapshot{
			Phase:           vpnd.PhaseWaitingTailscaled,
			Role:            cfg.Role,
			Mode:            d.Mode,
			ModeReason:      d.Reason,
			ControlURL:      controlURL,
			LastError:       msg,
			Warnings:        warnings,
			EnrollReachable: enrollReachable,
		}))
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("idoris-vpnd stopping")
			return nil
		}
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
		ControlURL:          controlURL,
		Hostname:            hostname,
		AcceptRoutes:        cfg.AcceptRoutes,
		AcceptDNS:           cfg.AcceptDNSValue(),
		AdvertiseTags:       cfg.AdvertiseTags,
		AdvertiseRoutes:     routes,
		RunSSH:              cfg.SSH,
		Takeover:            cfg.TakeoverValue(),
		LoginWhileStarting:  node.LoginWhileStarting,
		RecoverUnregistered: node.RecoverUnregistered,
		MarkRegistered:      node.markRegistered,
		Role:                cfg.Role,
		Identity:            ident,
		State:               binding,
		EnrollUnreachable:   !enrollReachable,
		Interval:            cfg.IntervalDuration(),
	}, log)
	if err != nil {
		return err
	}

	access, err := vpnd.StartLocalAccess(node.Dialer, cfg.Forwards, cfg.SOCKS5Listen, log)
	if err != nil {
		return err
	}
	defer func() { _ = access.Close() }()

	log.Info("idoris-vpnd starting", "version", version.Version, "mode", node.Mode, "mode_reason", node.Reason, "role", cfg.Role, "control_url", controlURL, "status_api", cfg.Listen, "os", runtime.GOOS)
	holder.Store(vpnd.View{Source: rec, Mode: node.Mode, ModeReason: node.Reason, Access: access})
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

func prepareKeys(cfg *vpnd.Config, log *slog.Logger) (vpnd.KeySource, string, vpnd.Identity, *vpnd.StateFile, bool, error) {
	controlURL := cfg.ControlURL
	var ident vpnd.Identity
	binding, err := openBinding(cfg)
	if err != nil {
		return nil, "", ident, nil, false, err
	}
	if cfg.EnrollURL == "" {
		if controlURL != "" {
			if err := binding.RememberControl(controlURL); err != nil {
				return nil, "", ident, nil, false, err
			}
		}
		return vpnd.StaticKey(cfg.AuthKey), controlURL, ident, binding, true, nil
	}
	ec := &enroll.Client{URL: cfg.EnrollURL, Token: cfg.EnrollToken, AllowInsecure: cfg.EnrollAllowInsecure}
	// Discover does not mint a key. It is the source of truth for tenant and role.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	d, derr := ec.Discover(ctx)
	cancel()
	saved := binding.Get().ControlURL
	if derr != nil {
		url, degraded, rerr := vpnd.ResolveStartupControl(cfg.ControlURL, "", saved, false)
		if rerr != nil {
			return nil, "", ident, nil, false, fmt.Errorf("%w (discovery: %v)", rerr, derr)
		}
		cfg.Role = vpnd.RoleWhileEnrollDown(cfg.Role, binding.Get().Role)
		log.Warn("enrollment discovery failed; resuming the saved control URL", "err", derr, "control_url", url, "role", cfg.Role)
		// The URL was not confirmed this start, so the binding is left as it was.
		return &enrollKeys{c: ec, cfg: cfg, log: log}, url, ident, binding, !degraded, nil
	}
	url, _, rerr := vpnd.ResolveStartupControl(cfg.ControlURL, d.ControlURL, saved, true)
	if rerr != nil {
		return nil, "", ident, nil, false, rerr
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
	log.Info("control url discovered", "tenant", d.Tenant, "role", role, "control_url", url)
	if err := binding.RememberControl(url); err != nil {
		return nil, "", ident, nil, false, err
	}
	return &enrollKeys{c: ec, cfg: cfg, log: log}, url, ident, binding, true, nil
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
	Mode                string
	Reason              string
	Backend             vpnd.Backend
	Dialer              vpnd.Dialer
	Hostname            string
	LoginWhileStarting  bool
	RecoverUnregistered bool
	markRegistered      func() error
	lock                *vpnd.ControllerLock
	close               func() error
}

func (n *runningNode) Close() error {
	if n == nil {
		return nil
	}
	var err error
	if n.close != nil {
		err = n.close()
	}
	if n.lock != nil {
		err = errors.Join(err, n.lock.Release())
	}
	return err
}

// openNode decides system vs embedded, then opens that backend.
// The probe is read-only. auto always probes. local-ai and gateway also
// probe when mode is system, and retry while tailscaled is down instead of
// starting an embedded node. advertise_routes is rejected again after auto
// resolves, before an embedded node is started.
func openNode(ctx context.Context, cfg *vpnd.Config, controlURL string, log *slog.Logger, onWait func(vpnd.ModeDecision)) (*runningNode, error) {
	req := cfg.Mode
	if req == "" {
		req = vpnd.ModeAuto
	}
	// local-ai and gateway already know they will drive the system backend.
	// Take that lock before the retry loop so a second daemon fails while the
	// first is still waiting for tailscaled. The probe itself only reads.
	var ctrl *vpnd.ControllerLock
	keepLock := false
	defer func() {
		if !keepLock && ctrl != nil {
			_ = ctrl.Release()
		}
	}()
	if vpnd.RequiresSystem(cfg.Role) {
		var lerr error
		ctrl, lerr = vpnd.LockSystem(cfg.TailscaleSocket)
		if lerr != nil {
			return nil, lerr
		}
	}
	d, err := vpnd.ProbeUntilReady(ctx, req, cfg.Role, cfg.TakeoverValue(), controlURL,
		func(pctx context.Context) vpnd.SystemView {
			probeCtx, cancel := context.WithTimeout(pctx, 3*time.Second)
			defer cancel()
			return vpnd.ProbeSystem(probeCtx, vpnd.NewLocalBackend(cfg.TailscaleSocket), controlURL)
		},
		onWait,
		func(sctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-sctx.Done():
				return sctx.Err()
			case <-t.C:
				return nil
			}
		},
	)
	if err != nil {
		return nil, err
	}
	log.Info("vpn mode", "mode", d.Mode, "reason", d.Reason, "role", cfg.Role)
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
		loginNow, recover, merr := vpnd.EmbeddedLoginMode(dir)
		if merr != nil {
			return nil, merr
		}
		if ctrl != nil {
			_ = ctrl.Release()
			ctrl = nil
		}
		ctrl, err = vpnd.LockEmbedded(dir)
		if err != nil {
			return nil, err
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
		keepLock = true
		return &runningNode{
			Mode:                d.Mode,
			Reason:              d.Reason,
			Backend:             emb.Backend(),
			Dialer:              emb,
			Hostname:            emb.Hostname(),
			LoginWhileStarting:  loginNow,
			RecoverUnregistered: recover,
			markRegistered:      func() error { return vpnd.MarkRegistrationComplete(dir) },
			lock:                ctrl,
			close:               emb.Close,
		}, nil
	}
	if ctrl == nil {
		ctrl, err = vpnd.LockSystem(cfg.TailscaleSocket)
		if err != nil {
			return nil, err
		}
	}
	keepLock = true
	return &runningNode{
		Mode:     vpnd.ModeSystem,
		Reason:   d.Reason,
		Backend:  vpnd.NewLocalBackend(cfg.TailscaleSocket),
		Dialer:   &net.Dialer{},
		Hostname: cfg.Hostname,
		lock:     ctrl,
		close:    func() error { return nil },
	}, nil
}
