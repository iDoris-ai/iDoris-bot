// idoris-vpn-enroll is the operator-side enrollment service. It is the only
// process that holds a Headscale API key; client daemons talk to it with
// per-tenant tokens and receive short-lived pre-auth keys.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/version"
)

func usage() {
	fmt.Fprintf(os.Stderr, `idoris-vpn-enroll %s — iDoris VPN enrollment service

Usage:
  idoris-vpn-enroll serve  --config FILE [--listen 127.0.0.1:8787]
  idoris-vpn-enroll token  new                        print a new token and its hash
  idoris-vpn-enroll invite --config FILE --entry NAME --enroll-url URL [--label L] [--hostname-hint H] [--allow-insecure]
  idoris-vpn-enroll revoke --config FILE --entry NAME (--label L | --hash-prefix HEX) [--allow-empty]
  idoris-vpn-enroll list-credentials --config FILE --entry NAME
  idoris-vpn-enroll tenant ensure --config FILE --name NAME   create the Headscale user, print its id
  idoris-vpn-enroll check  --config FILE              verify config and Headscale reachability
  idoris-vpn-enroll version

serve reloads the config on SIGHUP. An invalid file keeps the previous config.
A bad or empty headscale_api_key_file keeps the previous Headscale client.
invite prints one join code to stdout and nothing else. The code contains the
token; it is not written to the config file or the log.
list-credentials prints the label, a hash prefix, and created_at. It never
prints the token or the full hash.
Expiring or deleting a Headscale node does not revoke enrollment: the daemon
can ask for another pre-auth key. Revoke the credential first, then expire
or delete the node. revoke refuses to remove the last credential unless
--allow-empty is set. That leaves the entry with no credentials; it still
loads, and every token is rejected.

The Headscale API key is read from HEADSCALE_API_KEY or headscale_api_key_file.
`, version.Version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serveCmd(os.Args[2:])
	case "token":
		err = tokenCmd(os.Args[2:])
	case "invite":
		err = inviteCmd(os.Args[2:], os.Stdout)
	case "revoke":
		err = revokeCmd(os.Args[2:], os.Stdout)
	case "list-credentials":
		err = listCredentialsCmd(os.Args[2:], os.Stdout)
	case "tenant":
		err = tenantCmd(os.Args[2:])
	case "check":
		err = checkCmd(os.Args[2:])
	case "version", "--version":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "idoris-vpn-enroll:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*enroll.Config, error) {
	if path == "" {
		return nil, errors.New("--config is required")
	}
	b, err := enroll.ReadFileLocked(path)
	if err != nil {
		return nil, err
	}
	var cfg enroll.Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if v := os.Getenv("IDORIS_ENROLL_CONTROL_URL"); v != "" {
		cfg.ControlURL = v
	}
	if v := os.Getenv("IDORIS_ENROLL_HEADSCALE_URL"); v != "" {
		cfg.HeadscaleURL = v
	}
	if cfg.HeadscaleURL == "" {
		cfg.HeadscaleURL = cfg.ControlURL
	}
	return &cfg, nil
}

func apiKey(cfg *enroll.Config) (string, error) {
	if k := os.Getenv("HEADSCALE_API_KEY"); k != "" {
		return k, nil
	}
	if cfg.HeadscaleAPIKeyFile != "" {
		b, err := os.ReadFile(cfg.HeadscaleAPIKeyFile)
		if err != nil {
			return "", fmt.Errorf("headscale_api_key_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", errors.New("no Headscale API key: set HEADSCALE_API_KEY or headscale_api_key_file")
}

// controlProber adapts the Headscale client to enroll.ControlProber.
// The two packages cannot share the interface: enroll already imports headscale.
type controlProber struct{ c *headscale.Client }

func (p controlProber) ProbeControl(ctx context.Context) (enroll.ControlProbe, error) {
	st, err := p.c.ProbeControl(ctx)
	if err != nil {
		return enroll.ControlProbe{}, err
	}
	return enroll.ControlProbe{ExpiresAt: st.ExpiresAt, Known: st.Known}, nil
}

func hsClient(cfg *enroll.Config) (*headscale.Client, error) {
	k, err := apiKey(cfg)
	if err != nil {
		return nil, err
	}
	return &headscale.Client{BaseURL: cfg.HeadscaleURL, APIKey: k}, nil
}

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	listen := fs.String("listen", "127.0.0.1:8787", "listen address (put TLS termination in front)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	hs, err := hsClient(cfg)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := enroll.NewServer(*cfg, hs, log)
	if err != nil {
		return err
	}
	srv.SetControlProber(controlProber{hs})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	hsrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	notifyReload(hup)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			if err := reloadFromDisk(srv, *configPath, log); err != nil {
				log.Error("config reload rejected; keeping the previous config", "err", err)
				continue
			}
			log.Info("config reloaded")
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hsrv.Shutdown(sctx)
	}()
	log.Info("idoris-vpn-enroll listening", "addr", ln.Addr().String(), "control_url", cfg.ControlURL, "headscale", cfg.HeadscaleURL, "tenants", len(cfg.Tenants), "version", version.Version)
	if err := hsrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// reloadFromDisk reads the file again, reapplies environment overrides, and
// swaps the tenant config only when the result validates. When the file names
// headscale_api_key_file and HEADSCALE_API_KEY is unset, it also probes that
// key and swaps the client. A bad or empty key keeps the client already
// serving and is logged without the key. The caller must not treat that as a
// rejected reload: the tenant config has already been swapped.
func reloadFromDisk(srv *enroll.Server, path string, log *slog.Logger) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := srv.Reload(*cfg); err != nil {
		return err
	}
	reloadHeadscaleKey(srv, cfg, log)
	return nil
}

func reloadHeadscaleKey(srv *enroll.Server, cfg *enroll.Config, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if os.Getenv("HEADSCALE_API_KEY") != "" {
		return
	}
	path := strings.TrimSpace(cfg.HeadscaleAPIKeyFile)
	if path == "" {
		return
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's headscale_api_key_file
	if err != nil {
		log.Warn("headscale api key file unreadable; keeping the previous client", "path", path, "err", err)
		return
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		log.Warn("headscale api key file is empty; keeping the previous client", "path", path)
		return
	}
	hs := &headscale.Client{BaseURL: cfg.HeadscaleURL, APIKey: key}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := hs.ProbeControl(ctx); err != nil {
		var ae *headscale.APIError
		if errors.As(err, &ae) {
			log.Warn("headscale api key probe failed; keeping the previous client", "status", ae.Status)
			return
		}
		log.Warn("headscale api key probe failed; keeping the previous client")
		return
	}
	srv.SetMinter(hs)
	srv.SetControlProber(controlProber{hs})
	log.Info("headscale api key reloaded", "path", path)
}

func inviteCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	entry := fs.String("entry", "", "tenant entry name")
	hint := fs.String("hostname-hint", "", "optional hostname stored in the join code")
	label := fs.String("label", "", "credential label (default: hostname hint, else cred-<hash prefix>)")
	enrollURL := fs.String("enroll-url", "", "enrollment service URL stored in the join code")
	allow := fs.Bool("allow-insecure", false, "allow an http:// enroll URL (labs only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entry == "" || *enrollURL == "" {
		return errors.New("--entry and --enroll-url are required")
	}
	code, err := enroll.Invite(*configPath, *entry, *hint, *enrollURL, *label, *allow)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, code)
	return err
}

func revokeCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	entry := fs.String("entry", "", "tenant entry name")
	label := fs.String("label", "", "credential label to remove")
	prefix := fs.String("hash-prefix", "", "hex prefix of the token hash to remove")
	allowEmpty := fs.Bool("allow-empty", false, "remove the last credential and leave the entry with none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entry == "" {
		return errors.New("--entry is required")
	}
	if (*label == "") == (*prefix == "") {
		return errors.New("provide exactly one of --label or --hash-prefix")
	}
	removed, err := enroll.RemoveCredential(*configPath, *entry, enroll.CredentialMatch{Label: *label, HashPrefix: *prefix, AllowEmpty: *allowEmpty})
	if err != nil {
		return err
	}
	shown := removed.Label
	if shown == "" {
		shown = "-"
	}
	// HashPrefix only. The full hash and the token stay out of the terminal.
	_, err = fmt.Fprintf(stdout, "revoked %s %s %s\n", *entry, shown, enroll.HashPrefix(removed.Hash))
	return err
}

func listCredentialsCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("list-credentials", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	entry := fs.String("entry", "", "tenant entry name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entry == "" {
		return errors.New("--entry is required")
	}
	creds, err := enroll.ListCredentials(*configPath, *entry)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, enroll.FormatCredentialList(creds))
	return err
}

func tokenCmd(args []string) error {
	if len(args) < 1 || args[0] != "new" {
		return errors.New("token: expected `new`")
	}
	tok, err := enroll.NewToken()
	if err != nil {
		return err
	}
	fmt.Printf("token (give to the tenant, store in enroll_token_file):\n  %s\n", tok)
	fmt.Printf("hash  (put in tenants[].token_hashes):\n  %s\n", enroll.HashToken(tok))
	return nil
}

func tenantCmd(args []string) error {
	if len(args) < 1 || args[0] != "ensure" {
		return errors.New("tenant: expected `ensure`")
	}
	fs := flag.NewFlagSet("tenant ensure", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	name := fs.String("name", "", "tenant / Headscale user name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	hs, err := hsClient(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	u, err := hs.EnsureUser(ctx, *name)
	if err != nil {
		return err
	}
	fmt.Printf("headscale user %q id=%s\n", u.Name, u.ID)
	return nil
}

func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	hs, err := hsClient(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := hs.Health(ctx); err != nil {
		return fmt.Errorf("headscale health: %w", err)
	}
	users, err := hs.ListUsers(ctx, "")
	if err != nil {
		return fmt.Errorf("headscale api key: %w", err)
	}
	byID := map[string]string{}
	for _, u := range users {
		byID[u.ID] = u.Name
	}
	for _, t := range cfg.Tenants {
		n, ok := byID[t.HeadscaleUserID]
		if !ok {
			return fmt.Errorf("tenant %q: headscale user id %s does not exist", t.Name, t.HeadscaleUserID)
		}
		fmt.Printf("tenant %-20s -> headscale user %s (%s), %d token(s)\n", t.Name, t.HeadscaleUserID, n, len(t.TokenHashes))
	}
	fmt.Println("ok")
	return nil
}
