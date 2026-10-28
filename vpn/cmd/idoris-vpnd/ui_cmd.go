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

// uiOpenerTimeout is how long a browser launcher may run before the wizard
// treats it as started and leaves it alone. Tests shorten it.
var uiOpenerTimeout = 3 * time.Second

// uiStartBrowser is the process starter. Tests replace it and assert argv.
var uiStartBrowser = func(argv []string) error {
	return uiObserveOpener(argv, uiOpenerTimeout)
}

// uiObserveOpener starts argv and waits up to timeout. A non-zero exit or a
// failure to start is an error. A process that is still running when the
// timeout fires is left running: it may be the browser. timeout <= 0 uses
// the default of a few seconds.
func uiObserveOpener(argv []string, timeout time.Duration) error {
	if len(argv) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: argv[0] is open, xdg-open, or rundll32, chosen above
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return nil
	}
}

// uiGOOS selects the browser opener. Tests set it to cover Windows on another OS.
var uiGOOS = runtime.GOOS

// uiLauncherHint is printed when the wizard cannot open the launcher file.
// The page URL has no sign-in secret, so it is not a substitute.
const uiLauncherHint = "Open this file in a browser. It signs in, then loads the page. Opening the page URL by itself does not sign in:"

// uiLauncherFallback is one stderr line printed when a browser was started,
// including when the opener is still running. A launcher that exits 0 can
// still have failed to show a window.
const uiLauncherFallback = "If the browser did not open, open this file:"

// uiBrowserArgv is the command line used to open the launcher file.
// The secret is not an element: the file path is the only argument.
func uiBrowserArgv(goos, path string) []string {
	switch goos {
	case "darwin":
		return []string{"open", path}
	case "linux":
		return []string{"xdg-open", path}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", path}
	default:
		return nil
	}
}

func uiLauncherInstructions(path string) string {
	return uiLauncherHint + "\n" + path
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
	argv := uiBrowserArgv(uiGOOS, path)
	if len(argv) == 0 || open == nil {
		return uiLauncherInstructions(path), nil
	}
	if err := open(argv); err != nil {
		fmt.Fprintln(os.Stderr, "idoris-vpnd: browser:", err)
		return uiLauncherInstructions(path), nil
	}
	fmt.Fprintln(os.Stderr, uiLauncherFallback, path)
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
