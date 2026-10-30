package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

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
	printed, err := uiPrepareOpen(srv, *noOpen, uiStartBrowser)
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return err
	}
	fmt.Println(printed)
	return srv.Wait()
}

// uiLauncherRoot is the private directory that holds the auto-open HTML file.
// Tests replace it so they do not write into the real cache directory.
var uiLauncherRoot = func() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "idoris", "ui-launch"), nil
}

// uiStartBrowser is the process starter. Tests replace it and assert argv.
var uiStartBrowser = func(argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: argv[0] is open or xdg-open, chosen above
	return cmd.Start()
}

// uiBrowserArgv is the command line used to open the launcher file.
// The secret is not an element: the file path is the only argument.
func uiBrowserArgv(path string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"open", path}
	case "linux":
		return []string{"xdg-open", path}
	default:
		return nil
	}
}

// uiPrepareOpen starts the page. With noOpen it returns the hand-opened URL
// (secret in the fragment only). Otherwise it writes the launcher file and
// calls open with that path, and returns the page URL with no secret.
func uiPrepareOpen(srv *ui.Server, noOpen bool, open func([]string) error) (string, error) {
	manual, err := srv.Start()
	if err != nil {
		return "", err
	}
	if noOpen {
		return manual, nil
	}
	dir, err := uiLauncherRoot()
	if err != nil {
		return "", err
	}
	path, err := srv.WriteLauncher(dir)
	if err != nil {
		return "", err
	}
	if argv := uiBrowserArgv(path); len(argv) > 0 && open != nil {
		if err := open(argv); err != nil {
			fmt.Fprintln(os.Stderr, "idoris-vpnd: browser:", err)
		}
	}
	return srv.PageURL(), nil
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
