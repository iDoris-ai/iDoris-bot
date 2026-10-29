package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

const (
	qLocalAI = "Is THIS machine the Local AI host?"
	qDevice  = "Device IP on the office LAN:"
	qEnable  = "Enable this plan?"
)

// deps is the command layer's IO. Tests replace the host, detection, and discovery.
type deps struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	host     fileHost
	detect   func(mode string) (netdetect.Report, error)
	discover func(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error)
	home     func() (string, error)
	hostname func() (string, error)
	br       *bufio.Reader
}

func realDeps() deps {
	return deps{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		host: osHost{}, home: os.UserHomeDir, hostname: os.Hostname,
	}
}

func (d *deps) doDetect(mode string) (netdetect.Report, error) {
	if d.detect != nil {
		return d.detect(mode)
	}
	snap, err := netdetect.Collect(mode)
	if err != nil {
		return netdetect.Report{}, err
	}
	return netdetect.Detect(snap), nil
}

func (d *deps) doDiscover(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error) {
	if d.discover != nil {
		return d.discover(ctx, enrollURL, token, allowInsecure)
	}
	c := &enroll.Client{URL: enrollURL, Token: token, AllowInsecure: allowInsecure}
	return c.Discover(ctx)
}

func (d *deps) readLine() (string, error) {
	if d.stdin == nil {
		return "", errors.New("no terminal input")
	}
	if d.br == nil {
		d.br = bufio.NewReader(d.stdin)
	}
	line, err := d.br.ReadString('\n')
	if line == "" && err != nil {
		if errors.Is(err, io.EOF) {
			return "", errors.New("unexpected end of input")
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (d *deps) askYes(q string) (bool, error) {
	if _, err := fmt.Fprintf(d.stdout, "%s [y/N] ", q); err != nil {
		return false, err
	}
	line, err := d.readLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func joinCmd(args []string, d deps) error {
	panic("stub")
}
func (d *deps) ask(q string) (string, error) {
	if _, err := fmt.Fprintf(d.stdout, "%s ", q); err != nil {
		return "", err
	}
	return d.readLine()
}

func gatewayCmd(args []string, d deps) error {
	if len(args) < 1 {
		return errors.New("gateway: expected detect, setup, or apply")
	}
	switch args[0] {
	case "detect":
		return d.detectCmd(args[1:])
	case "setup":
		return d.setupCmd(args[1:])
	case "apply":
		return d.applyCmd(args[1:])
	default:
		return fmt.Errorf("gateway: unknown action %q", args[0])
	}
}

func (d *deps) detectCmd(args []string) error {
	fs := flag.NewFlagSet("gateway detect", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	asJSON := fs.Bool("json", false, "print the detection report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := d.doDetect("system")
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(d.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	d.printReport(rep)
	return nil
}

func (d *deps) setupCmd(args []string) error {
	fs := flag.NewFlagSet("gateway setup", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	yes := fs.Bool("yes", false, "this machine is not the Local AI host; apply without prompting")
	noService := fs.Bool("no-service", false, "do not install the user service")
	whole := fs.Bool("whole-subnet", false, "advertise the whole LAN")
	allowInsecure := fs.Bool("allow-insecure", false, "allow an http:// enrollment URL")
	configPath := fs.String("config", "", "daemon config path")
	var devices stringList
	fs.Var(&devices, "device", "office device IP (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *whole && len(devices) > 0 {
		return errors.New("gateway setup: pass --device or --whole-subnet, not both")
	}
	paths, err := d.paths(*configPath)
	if err != nil {
		return err
	}
	cfg, err := d.readConfig(paths.config)
	if err != nil {
		return fmt.Errorf("gateway setup: %w (run idoris-vpnd join <code> first)", err)
	}
	if cfg.EnrollURL == "" {
		return errors.New("gateway setup: config has no enroll_url")
	}
	token, err := d.readToken(cfg)
	if err != nil {
		return err
	}
	insecure := cfg.EnrollAllowInsecure || *allowInsecure
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	disc, err := d.doDiscover(ctx, cfg.EnrollURL, token, insecure)
	cancel()
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	host, err := d.nodeHostname(cfg.Hostname)
	if err != nil {
		return err
	}
	localAI := false
	if !*yes {
		localAI, err = d.askYes(qLocalAI)
		if err != nil {
			return err
		}
	}
	payload := join.Payload{EnrollURL: cfg.EnrollURL, Token: token, Tenant: disc.Tenant, HostnameHint: host}
	if localAI {
		plan, err := gateway.BuildPlan(gateway.Request{ThisMachineIsLocalAI: true, Tenant: disc.Tenant, Hostname: host})
		if err != nil {
			return err
		}
		return d.applyPlan(plan, paths, payload, insecure, *noService, *yes)
	}
	devs := []string(devices)
	if !*yes && !*whole && len(devs) == 0 {
		line, err := d.ask(qDevice)
		if err != nil {
			return err
		}
		if line == "" {
			return errors.New("gateway setup: a device IP or --whole-subnet is required")
		}
		devs = []string{line}
	}
	if *yes && !*whole && len(devs) == 0 {
		return errors.New("gateway setup: --yes needs --device or --whole-subnet")
	}
	return d.gatewayApply(gateway.Request{
		DeviceIPs: devs, WholeSubnet: *whole, Approved: disc.LANCIDRs, Tenant: disc.Tenant, Hostname: host,
	}, paths, token, cfg.EnrollURL, insecure, *noService, *yes)
}

func (d *deps) applyCmd(args []string) error {
	fs := flag.NewFlagSet("gateway apply", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	planPath := fs.String("plan", "", "plan JSON written by setup or join")
	noService := fs.Bool("no-service", false, "do not install the user service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planPath == "" {
		return errors.New("gateway apply: --plan is required")
	}
	raw, err := d.host.ReadFile(*planPath)
	if err != nil {
		return err
	}
	plan, err := gateway.LoadPlan(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	token := ""
	if plan.TokenFile != "" {
		if b, err := d.host.ReadFile(plan.TokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	if token != "" && bytes.Contains(raw, []byte(token)) {
		return errors.New("gateway apply: refusing a plan file that contains the enrollment token")
	}
	res, err := gateway.Apply(plan, d.host, gateway.ApplyOptions{Token: token, NoService: *noService, PlanPath: *planPath})
	if err != nil {
		return err
	}
	d.printResult(res)
	return nil
}

type idorisPaths struct {
	config string
	token  string
	plan   string
}

func (d *deps) paths(config string) (idorisPaths, error) {
	home, err := d.home()
	if err != nil || home == "" {
		return idorisPaths{}, fmt.Errorf("home directory: %w", err)
	}
	base := filepath.Join(home, ".idoris")
	p := idorisPaths{
		config: filepath.Join(base, "vpn.json"),
		token:  filepath.Join(base, "enroll.token"),
		plan:   filepath.Join(base, "gateway-plan.json"),
	}
	if config != "" {
		p.config = config
	}
	return p, nil
}

func (d *deps) nodeHostname(hint string) (string, error) {
	if strings.TrimSpace(hint) != "" {
		return strings.TrimSpace(hint), nil
	}
	if d.hostname == nil {
		return "", errors.New("hostname is empty")
	}
	h, err := d.hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return strings.TrimSpace(h), nil
}

func (d *deps) gatewayApply(req gateway.Request, paths idorisPaths, token, enrollURL string, allowInsecure, noService, yes bool) error {
	rep, err := d.doDetect("system")
	if err != nil {
		return err
	}
	d.printReport(rep)
	req.Detection = rep
	plan, err := gateway.BuildPlan(req)
	if err != nil {
		return err
	}
	if plan.Blocked {
		_, _ = fmt.Fprintln(d.stdout, plan.BlockReason)
		return errors.New(plan.BlockReason)
	}
	payload := join.Payload{EnrollURL: enrollURL, Token: token}
	return d.applyPlan(plan, paths, payload, allowInsecure, noService, yes)
}

func (d *deps) applyPlan(plan gateway.Plan, paths idorisPaths, payload join.Payload, allowInsecure, noService, yes bool) error {
	plan.EnrollURL = payload.EnrollURL
	plan.TokenFile = paths.token
	plan.ConfigPath = paths.config
	plan.AllowInsecure = allowInsecure
	d.printPlan(plan)
	if !yes {
		ok, err := d.askYes(qEnable)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not applied")
		}
	}
	res, err := gateway.Apply(plan, d.host, gateway.ApplyOptions{
		Token: payload.Token, NoService: noService, PlanPath: paths.plan,
	})
	if err != nil {
		return err
	}
	d.printResult(res)
	return nil
}

func (d *deps) printReport(rep netdetect.Report) {
	_, _ = fmt.Fprintf(d.stdout, "platform: %s\ngateway-supported: %v\n", rep.Platform, rep.GatewaySupported)
	for _, c := range rep.Candidates {
		mark := ""
		if rep.Recommended != nil && c.Network == rep.Recommended.Network && c.Addr == rep.Recommended.Addr {
			mark = " recommended"
		}
		_, _ = fmt.Fprintf(d.stdout, "candidate:%s %s %s gateway %s\n", mark, c.Name, c.Network, c.Gateway)
	}
	for _, c := range rep.Checks {
		mark := "fail"
		if c.OK {
			mark = "ok"
		}
		_, _ = fmt.Fprintf(d.stdout, "check: %s %s %s\n", c.ID, mark, c.Detail)
		if !c.OK && c.Fix != "" {
			_, _ = fmt.Fprintf(d.stdout, "fix: %s\n", c.Fix)
		}
	}
}

func (d *deps) printPlan(plan gateway.Plan) {
	_, _ = fmt.Fprintf(d.stdout, "role: %s\n", plan.Role)
	if len(plan.Routes) == 0 {
		_, _ = fmt.Fprintln(d.stdout, "routes: (none)")
	} else {
		_, _ = fmt.Fprintf(d.stdout, "routes: %s\n", strings.Join(plan.Routes, ","))
	}
	if plan.WillAutoApprove {
		_, _ = fmt.Fprintln(d.stdout, "auto-approve: yes")
	} else {
		_, _ = fmt.Fprintln(d.stdout, "auto-approve: no")
	}
	if plan.AdminCommand != "" {
		_, _ = fmt.Fprintf(d.stdout, "admin: %s\n", plan.AdminCommand)
	}
	for _, w := range plan.Warnings {
		_, _ = fmt.Fprintf(d.stdout, "warning: %s: %s\n", w.Code, w.Text)
	}
}

func (d *deps) printResult(res gateway.ApplyResult) {
	_, _ = fmt.Fprintf(d.stdout, "config: %s\n", res.ConfigPath)
	if res.ServiceInstalled {
		_, _ = fmt.Fprintln(d.stdout, "service: installed")
	}
	if res.IPForwardApplied {
		_, _ = fmt.Fprintln(d.stdout, "ip-forward: enabled")
	}
	if res.SudoCommand != "" {
		_, _ = fmt.Fprintf(d.stdout, "sudo: %s\n", res.SudoCommand)
		_, _ = fmt.Fprintln(d.stdout, "Forwarding was not changed. Re-run the sudo command as root; this program will not escalate by itself.")
	}
}

func (d *deps) readConfig(path string) (vpnd.Config, error) {
	b, err := d.host.ReadFile(path)
	if err != nil {
		return vpnd.Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg vpnd.Config
	if err := dec.Decode(&cfg); err != nil {
		return vpnd.Config{}, err
	}
	return cfg, nil
}

func (d *deps) readToken(cfg vpnd.Config) (string, error) {
	if cfg.EnrollTokenFile != "" {
		b, err := d.host.ReadFile(cfg.EnrollTokenFile)
		if err != nil {
			return "", fmt.Errorf("enrollment token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", errors.New("enrollment token file is empty")
		}
		return tok, nil
	}
	if strings.TrimSpace(cfg.EnrollToken) == "" {
		return "", errors.New("config has no enrollment token")
	}
	return strings.TrimSpace(cfg.EnrollToken), nil
}
