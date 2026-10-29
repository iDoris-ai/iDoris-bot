package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/ui"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func uiCmd(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noOpen := fs.Bool("no-open", false, "print the local URL without opening a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv, err := ui.New(ui.Options{
		EUID:     os.Geteuid(),
		LoginUID: ui.CurrentLoginUID(),
		Services: liveServices(),
	})
	if err != nil {
		return err
	}
	page, err := srv.Start()
	if err != nil {
		return err
	}
	fmt.Println(page)
	if !*noOpen {
		openBrowser(page)
	}
	return srv.Wait()
}

func liveServices() ui.Services {
	return ui.Services{
		Detect: func() (netdetect.Report, error) {
			snap, err := netdetect.Collect("system")
			if err != nil {
				return netdetect.Report{}, err
			}
			return netdetect.Detect(snap), nil
		},
		Probe: func(ctx context.Context, ip string) (netdetect.ProbeResult, error) {
			return netdetect.ProbeDevice(ctx, ip, nil)
		},
		Discover: func(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error) {
			return (&enroll.Client{URL: enrollURL, Token: token, AllowInsecure: allowInsecure}).Discover(ctx)
		},
		Apply: func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
			return gateway.Apply(plan, osHost{}, opt)
		},
		Status: func(ctx context.Context) (map[string]any, error) {
			return vpnd.QueryStatus(ctx, vpnd.DefaultListen())
		},
		Home:     os.UserHomeDir,
		Hostname: os.Hostname,
	}
}

func openBrowser(page string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", page)
	case "linux":
		cmd = exec.Command("xdg-open", page)
	default:
		return
	}
	_ = cmd.Start()
}
