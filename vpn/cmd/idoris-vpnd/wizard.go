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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
	"golang.org/x/term"
)

const (
	qLocalAI = "Is THIS machine the Local AI host?"
	qDevice  = "Device IP on the office LAN:"
	qEnable  = "Enable this plan?"
)

// deps is the command layer's IO. Tests replace the host, detection, and discovery.
type deps struct {
	stdin        io.Reader
	stdout       io.Writer
	stderr       io.Writer
	host         fileHost
	detect       func(mode string) (netdetect.Report, error)
	discover     func(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error)
	home         func() (string, error)
	hostname     func() (string, error)
	term         func() bool
	readPassword func() (string, error)
	br           *bufio.Reader
}

func realDeps() deps {
	return deps{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		host: osHost{}, home: os.UserHomeDir, hostname: os.Hostname,
		term: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		readPassword: func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
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
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	yes := fs.Bool("yes", false, "accept the recommended plan without prompting")
	noService := fs.Bool("no-service", false, "do not install the user service")
	replace := fs.Bool("replace", false, "replace a config enrolled with a different enrollment URL")
	roleOverride := fs.String("role-override", "", "member|local-ai|gateway|admin")
	allowInsecure := fs.Bool("allow-insecure", false, "accept an http:// enrollment URL (labs only)")
	whole := fs.Bool("whole-subnet", false, "advertise the whole LAN instead of device /32s")
	codeFile := fs.String("code-file", "", "read the join code from this file instead of the command line")
	codeStdin := fs.Bool("code-stdin", false, "read the join code from one line on stdin")
	expect := fs.String("expect-authority", "", "refuse the code unless its enrollment host[:port] matches")
	var devices stringList
	fs.Var(&devices, "device", "office device IP to advertise as /32 (repeatable)")
	configPath := fs.String("config", "", "daemon config path (default ~/.idoris/vpn.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *roleOverride != "" && !join.ValidRole(*roleOverride) {
		return fmt.Errorf("join: role %q is not valid", *roleOverride)
	}
	// The code is a secret. Read it without putting it in argv, then never print it.
	code, err := readJoinCode(fs, &d, *codeFile, *codeStdin)
	if err != nil {
		return err
	}
	payload, err := join.Decode(code, join.Options{AllowInsecure: *allowInsecure})
	if err != nil {
		return err
	}
	role := payload.Role
	if *roleOverride != "" {
		role = *roleOverride
	}
	return d.runJoin(joinOpt{
		payload: payload, role: role, override: *roleOverride,
		yes: *yes, noService: *noService, replace: *replace,
		devices: []string(devices), whole: *whole, configPath: *configPath,
		expect: *expect,
	})
}

type joinOpt struct {
	payload    join.Payload
	role       string
	override   string
	discovered string
	yes        bool
	noService  bool
	replace    bool
	devices    []string
	whole      bool
	configPath string
	expect     string
}

func (d *deps) runJoin(opt joinOpt) error {
	if opt.whole && len(opt.devices) > 0 {
		return errors.New("join: pass --device or --whole-subnet, not both")
	}
	// Show the enrollment host and get a yes before the token leaves the machine.
	authority, err := enrollmentAuthority(opt.payload.EnrollURL)
	if err != nil {
		return err
	}
	if err := d.confirmAuthority(authority, opt.expect, opt.yes); err != nil {
		return err
	}
	paths, err := d.paths(opt.configPath)
	if err != nil {
		return err
	}
	allow := strings.HasPrefix(opt.payload.EnrollURL, "http://")
	approved, discovered, err := d.discoverJoin(opt.payload.EnrollURL, opt.payload.Token, allow)
	if err != nil {
		_, _ = fmt.Fprintf(d.stderr, "discover failed (%s); continuing without the pre-approved list\n", err)
		approved = nil
		discovered = ""
	}
	role, err := gateway.ReconcileRole(opt.payload.Role, opt.override, discovered)
	if err != nil {
		return err
	}
	opt.role = role
	opt.discovered = discovered
	host, err := d.nodeHostname(opt.payload.HostnameHint)
	if err != nil {
		return err
	}
	switch opt.role {
	case join.RoleMember, join.RoleAdmin:
		plan, err := gateway.SimplePlan(opt.role, opt.payload.Tenant, host)
		if err != nil {
			return err
		}
		return d.applyPlan(plan, paths, opt.payload, allow, opt.noService, opt.yes, opt.replace)
	case join.RoleLocalAI:
		if err := gateway.ValidateRoleChoice(credentialRole(opt), true); err != nil {
			return err
		}
		plan, err := gateway.BuildPlan(gateway.Request{
			ThisMachineIsLocalAI: true,
			Tenant:               opt.payload.Tenant,
			Hostname:             host,
		})
		if err != nil {
			return err
		}
		return d.applyPlan(plan, paths, opt.payload, allow, opt.noService, opt.yes, opt.replace)
	case join.RoleGateway:
		localAI := false
		if !opt.yes {
			localAI, err = d.askYes(qLocalAI)
			if err != nil {
				return err
			}
		}
		if err := gateway.ValidateRoleChoice(credentialRole(opt), localAI); err != nil {
			return err
		}
		if localAI {
			plan, err := gateway.BuildPlan(gateway.Request{
				ThisMachineIsLocalAI: true,
				Tenant:               opt.payload.Tenant,
				Hostname:             host,
			})
			if err != nil {
				return err
			}
			return d.applyPlan(plan, paths, opt.payload, allow, opt.noService, opt.yes, opt.replace)
		}
		devices := opt.devices
		if !opt.yes && !opt.whole && len(devices) == 0 {
			line, err := d.ask(qDevice)
			if err != nil {
				return err
			}
			if line == "" {
				return errors.New("join: a gateway needs a device IP or --whole-subnet")
			}
			devices = []string{line}
		}
		if opt.yes && !opt.whole && len(devices) == 0 {
			return errors.New("join: --yes on a gateway needs --device or --whole-subnet")
		}
		return d.gatewayApply(gateway.Request{
			DeviceIPs:   devices,
			WholeSubnet: opt.whole,
			Approved:    approved,
			Tenant:      opt.payload.Tenant,
			Hostname:    host,
		}, paths, opt.payload.Token, opt.payload.EnrollURL, allow, opt.noService, opt.yes, opt.replace)
	default:
		return fmt.Errorf("join: role %q is not valid", opt.role)
	}
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
	replace := fs.Bool("replace", false, "replace a config enrolled with a different enrollment URL")
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
		return fmt.Errorf("gateway setup: %w (run idoris-vpnd join --code-file <path> first)", err)
	}
	if cfg.EnrollURL == "" {
		return errors.New("gateway setup: config has no enroll_url")
	}
	token, err := d.readToken(cfg)
	if err != nil {
		return err
	}
	authority, err := enrollmentAuthority(cfg.EnrollURL)
	if err != nil {
		return err
	}
	if err := d.confirmAuthority(authority, "", *yes); err != nil {
		return err
	}
	insecure := cfg.EnrollAllowInsecure || *allowInsecure
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	disc, err := d.doDiscover(ctx, cfg.EnrollURL, token, insecure)
	cancel()
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if disc == nil {
		return errors.New("discover: empty response")
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
	if disc.Role != "" {
		if err := gateway.ValidateRoleChoice(disc.Role, localAI); err != nil {
			return err
		}
	}
	payload := join.Payload{EnrollURL: cfg.EnrollURL, Token: token, Tenant: disc.Tenant, HostnameHint: host}
	if localAI {
		plan, err := gateway.BuildPlan(gateway.Request{ThisMachineIsLocalAI: true, Tenant: disc.Tenant, Hostname: host})
		if err != nil {
			return err
		}
		return d.applyPlan(plan, paths, payload, insecure, *noService, *yes, *replace)
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
	}, paths, token, cfg.EnrollURL, insecure, *noService, *yes, *replace)
}

// readPlanHandoff stats the plan file the unprivileged wizard wrote.
// Tests replace it. The real function does not follow a symlink.
var readPlanHandoff = gateway.ReadPlanHandoff

func (d *deps) applyCmd(args []string) error {
	fs := flag.NewFlagSet("gateway apply", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	planPath := fs.String("plan", "", "plan JSON written by setup or join")
	noService := fs.Bool("no-service", false, "do not install the user service")
	replace := fs.Bool("replace", false, "replace a config enrolled with a different enrollment URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planPath == "" {
		return errors.New("gateway apply: --plan is required")
	}
	// Root only enables forwarding. The user's config, token and plan were
	// written before sudo, and this process must not rewrite them or demand
	// that the user's directory be root-owned.
	if d.host.IsRoot() {
		return d.applyPrivileged(*planPath)
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
	res, err := gateway.Apply(plan, d.host, gateway.ApplyOptions{
		Token: token, NoService: *noService, PlanPath: *planPath, ReplaceExisting: *replace,
	})
	if err != nil {
		return err
	}
	d.printResult(res)
	return nil
}

// applyPrivileged is `sudo idoris-vpnd gateway apply`. It checks the plan file
// the unprivileged wizard wrote, then enables forwarding when the plan needs
// it. It does not install the service or write under the user's directory.
func (d *deps) applyPrivileged(planPath string) error {
	h, err := readPlanHandoff(planPath)
	if err != nil {
		return err
	}
	if err := gateway.CheckPlanHandoff(h); err != nil {
		return err
	}
	raw, err := d.host.ReadFile(planPath)
	if err != nil {
		return err
	}
	plan, err := gateway.LoadPlan(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if plan.TokenFile != "" {
		if b, err := d.host.ReadFile(plan.TokenFile); err == nil {
			token := strings.TrimSpace(string(b))
			if token != "" && bytes.Contains(raw, []byte(token)) {
				return errors.New("gateway apply: refusing a plan file that contains the enrollment token")
			}
		}
	}
	res := gateway.ApplyResult{ConfigPath: plan.ConfigPath, PlanPath: planPath, TokenFile: plan.TokenFile}
	if gateway.PlanEnablesForward(plan) {
		if d.host.GOOS() != "linux" {
			return errors.New("gateway: refusing to enable forwarding on a non-Linux host")
		}
		if err := d.host.EnableIPForward(gateway.IPForwardConf, gateway.IPForwardBody); err != nil {
			return err
		}
		res.IPForwardApplied = true
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
	config = strings.TrimSpace(config)
	if config != "" {
		abs, err := filepath.Abs(config)
		if err != nil {
			return idorisPaths{}, fmt.Errorf("config path: %w", err)
		}
		config = abs
	}
	home, err := d.home()
	if err != nil || home == "" {
		return idorisPaths{}, fmt.Errorf("home directory: %w", err)
	}
	p := gateway.PathsFor(home, config)
	return idorisPaths{config: p.Config, token: p.Token, plan: p.Plan}, nil
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

func (d *deps) discoverJoin(enrollURL, token string, allowInsecure bool) (approved []string, role string, err error) {
	if enrollURL == "" || token == "" {
		return nil, "", errors.New("enrollment URL or token is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	disc, err := d.doDiscover(ctx, enrollURL, token, allowInsecure)
	if err != nil {
		return nil, "", err
	}
	if disc == nil {
		return nil, "", errors.New("discovery returned nothing")
	}
	return disc.LANCIDRs, disc.Role, nil
}

func (d *deps) gatewayApply(req gateway.Request, paths idorisPaths, token, enrollURL string, allowInsecure, noService, yes, replace bool) error {
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
	return d.applyPlan(plan, paths, payload, allowInsecure, noService, yes, replace)
}

func (d *deps) applyPlan(plan gateway.Plan, paths idorisPaths, payload join.Payload, allowInsecure, noService, yes, replace bool) error {
	plan.EnrollURL = payload.EnrollURL
	plan.TokenFile = paths.token
	plan.ConfigPath = paths.config
	plan.AllowInsecure = allowInsecure
	if replace {
		if raw, err := d.host.ReadFile(paths.config); err == nil {
			gateway.NoteControlPinDrop(&plan, gateway.PreviousEnrollURL(raw))
		}
	}
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
		Token: payload.Token, NoService: noService, PlanPath: paths.plan, ReplaceExisting: replace,
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
	if res.Role != "" || res.EnrollURL != "" || res.Hostname != "" {
		_, _ = fmt.Fprintf(d.stdout, "identity: role=%s hostname=%s enroll=%s\n", res.Role, res.Hostname, res.EnrollURL)
	}
	if res.ControlURL != "" {
		_, _ = fmt.Fprintf(d.stdout, "control: %s\n", res.ControlURL)
	}
	if res.ServiceInstalled {
		_, _ = fmt.Fprintf(d.stdout, "service: installed role=%s hostname=%s enroll=%s\n", res.Role, res.Hostname, res.EnrollURL)
	}
	if res.IPForwardApplied {
		_, _ = fmt.Fprintln(d.stdout, "ip-forward: enabled")
	}
	if res.SudoCommand != "" {
		_, _ = fmt.Fprintf(d.stdout, "sudo: %s\n", res.SudoCommand)
		_, _ = fmt.Fprintln(d.stdout, "Forwarding was not changed. Re-run the sudo command as root; this program will not escalate by itself.")
	}
	for _, line := range res.AccessInfo {
		_, _ = fmt.Fprintf(d.stdout, "access: %s\n", line)
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

// readJoinCode takes the join code from one of the safe inputs. A positional
// argument still works, and prints a warning: argv and shell history are
// visible to other users. The three inputs are mutually exclusive.
func readJoinCode(fs *flag.FlagSet, d *deps, codeFile string, codeStdin bool) (string, error) {
	n := 0
	if codeFile != "" {
		n++
	}
	if codeStdin {
		n++
	}
	if fs.NArg() > 0 {
		n++
	}
	if n > 1 || fs.NArg() > 1 {
		return "", errors.New("join: pass only one of a positional code, --code-file, or --code-stdin")
	}
	if codeFile != "" {
		b, err := d.host.ReadFile(codeFile)
		if err != nil {
			return "", fmt.Errorf("join: --code-file: %w", err)
		}
		return nonemptyCode(firstLine(string(b)))
	}
	if codeStdin {
		line, err := d.readLine()
		if err != nil {
			return "", err
		}
		return nonemptyCode(line)
	}
	if fs.NArg() == 1 {
		_, _ = fmt.Fprintln(d.stderr, "warning: the join code was passed as an argument and can be read by other users from the process list and shell history; use --code-file or --code-stdin")
		return nonemptyCode(fs.Arg(0))
	}
	if d.term != nil && d.term() {
		if _, err := fmt.Fprintln(d.stdout, "Join code (input hidden):"); err != nil {
			return "", err
		}
		if d.readPassword == nil {
			return "", errors.New("join: cannot read a hidden join code")
		}
		line, err := d.readPassword()
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintln(d.stdout)
		return nonemptyCode(strings.TrimSpace(line))
	}
	return "", errors.New("join: pass --code-file or --code-stdin")
}

func nonemptyCode(code string) (string, error) {
	if strings.TrimSpace(code) == "" {
		return "", errors.New("join: join code is empty")
	}
	return strings.TrimSpace(code), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// enrollmentAuthority is the host[:port] of the enrollment URL. A join code
// does not authenticate that host; the operator has to recognise it.
func enrollmentAuthority(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", errors.New("join: enrollment URL has no authority")
	}
	return u.Host, nil
}

func (d *deps) confirmAuthority(authority, expect string, yes bool) error {
	if _, err := fmt.Fprintf(d.stdout, "enrollment-authority: %s\n", authority); err != nil {
		return err
	}
	if expect != "" && !strings.EqualFold(strings.TrimSpace(expect), authority) {
		return fmt.Errorf("enrollment authority %s does not match --expect-authority %s", authority, expect)
	}
	if yes {
		return nil
	}
	ok, err := d.askYes(fmt.Sprintf("Contact enrollment authority %s?", authority))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not applied")
	}
	return nil
}

func credentialRole(opt joinOpt) string {
	if opt.discovered != "" {
		return opt.discovered
	}
	return opt.payload.Role
}
