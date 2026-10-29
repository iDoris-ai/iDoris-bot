package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// windowsExitWait is how long an active reinstall waits for the scheduled
// task's process to leave the installed image. Tests shorten it.
var windowsExitWait = 30 * time.Second

// windowsPollGap is the pause between tasklist polls.
var windowsPollGap = 200 * time.Millisecond

var (
	windowsNow   = time.Now
	windowsSleep = time.Sleep
)

// protectWindowsInstallFn applies the machine DACL. Tests replace it to
// record whether the staging directory was still empty. Production is
// protectWindowsInstall.
var protectWindowsInstallFn = protectWindowsInstall

// windowsReplaceSpec is one Windows install with explicit paths, so the
// order can be tested on a non-Windows host. StagingDir is a sibling of the
// live tree, never a directory inside it.
type windowsReplaceSpec struct {
	SrcExe     string
	LiveExe    string
	ExeDir     string
	ConfigSrc  string
	LiveDir    string
	LiveConfig string
	StagingDir string
	Active     bool
	// SelfPID is set when this process is running the installed image.
	// The wait treats that pid as the installer and does not replace LiveExe.
	SelfPID int
}

func windowsStagingPath() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	parent := filepath.Dir(windowsConfigDir)
	return filepath.Join(parent, "idoris-install-"+hex.EncodeToString(b[:])), nil
}

func sameInstallExe(src, live string) bool {
	if src == "" || live == "" {
		return false
	}
	a, err1 := filepath.Abs(src)
	b, err2 := filepath.Abs(live)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// replaceWindowsTask stages the new install, and only then stops an active
// task, waits for its process, and commits. A failure before the commit
// deletes the staging directory and does not write the live tree.
func replaceWindowsTask(spec windowsReplaceSpec) error {
	if spec.StagingDir == "" || spec.LiveDir == "" || spec.LiveExe == "" {
		return fmt.Errorf("windows install: missing path")
	}
	live := filepath.Clean(spec.LiveDir)
	stage := filepath.Clean(spec.StagingDir)
	if stage == live || strings.HasPrefix(stage, live+string(filepath.Separator)) {
		return fmt.Errorf("windows install: staging directory %s is inside %s", spec.StagingDir, spec.LiveDir)
	}
	if err := os.MkdirAll(filepath.Dir(stage), 0o750); err != nil {
		return err
	}
	if err := os.Mkdir(stage, 0o750); err != nil {
		return err
	}
	// Windows ignores the 0750 mode. The inherited ProgramData ACL would
	// let another local user read credential bytes, so the empty directory
	// is restricted and verified before any file is copied in. Per-file
	// ACLs are applied again once the staged files exist.
	if err := protectWindowsInstallFn(stage, "", "", "", nil); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_ = os.RemoveAll(stage)
		}
	}()

	runExe := spec.LiveExe
	stagedName := filepath.Base(spec.LiveExe)
	if spec.SelfPID != 0 {
		stagedName = fmt.Sprintf("idoris-vpnd-%d.exe", windowsNow().UnixNano())
		runExe = filepath.Join(spec.ExeDir, stagedName)
	}
	stagedExe := filepath.Join(stage, stagedName)
	if err := copyInstallFile(spec.SrcExe, stagedExe, 0o755); err != nil {
		return err
	}
	cfg, err := os.ReadFile(spec.ConfigSrc) //nolint:gosec // operator-chosen config, staged before it touches the live tree
	if err != nil {
		return err
	}
	body, creds, err := stageWindowsConfig(cfg, stage)
	if err != nil {
		return err
	}
	body, err = retargetStagedConfig(body, stage, spec.LiveDir)
	if err != nil {
		return err
	}
	stagedConfig := filepath.Join(stage, "vpn.json")
	if err := os.WriteFile(stagedConfig, body, 0o600); err != nil { //nolint:gosec // G306: staged config is mode 0600 before it is moved onto the live path
		return err
	}
	// Secrets exist only in the staging directory. Protect that directory
	// before the task is stopped. On non-Windows this is a no-op.
	if err := protectWindowsInstallFn(stage, stagedConfig, "", stagedExe, creds); err != nil {
		return err
	}

	ended := false
	if spec.Active {
		if out, err := runServiceCommand("schtasks", "/End", "/TN", windowsTaskName); err != nil {
			return fmt.Errorf("schtasks /End: %w: %s", err, strings.TrimSpace(string(out)))
		}
		ended = true
		if err := waitWindowsImageExit(filepath.Base(spec.LiveExe), spec.SelfPID); err != nil {
			_, _ = runServiceCommand("schtasks", "/Run", "/TN", windowsTaskName)
			return err
		}
	}

	if err := os.MkdirAll(spec.ExeDir, 0o755); err != nil { //nolint:gosec // G301: installed program directory
		return err
	}
	if err := replaceFile(stagedExe, runExe); err != nil {
		if ended {
			_, _ = runServiceCommand("schtasks", "/Run", "/TN", windowsTaskName)
		}
		return err
	}
	if err := chownSystemRoot(runExe); err != nil {
		return err
	}
	if err := os.MkdirAll(spec.LiveDir, 0o750); err != nil { //nolint:gosec // G301: ProgramData\idoris
		return err
	}
	var liveCreds []string
	for _, c := range creds {
		dest := filepath.Join(spec.LiveDir, filepath.Base(c))
		if err := replaceFile(c, dest); err != nil {
			return err
		}
		if err := chownSystemRoot(dest); err != nil {
			return err
		}
		liveCreds = append(liveCreds, dest)
	}
	if err := replaceFile(stagedConfig, spec.LiveConfig); err != nil {
		return err
	}
	if err := protectWindowsInstallFn(spec.LiveDir, spec.LiveConfig, spec.ExeDir, runExe, liveCreds); err != nil {
		return err
	}
	args := renderSchtasksCreateIn(runExe, spec.LiveConfig, spec.LiveDir)
	if out, err := runServiceCommand("schtasks", args...); err != nil {
		return fmt.Errorf("schtasks: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if spec.Active {
		if out, err := runServiceCommand("schtasks", "/Run", "/TN", windowsTaskName); err != nil {
			return fmt.Errorf("schtasks /Run: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	commit = true
	_ = os.RemoveAll(stage)
	return nil
}

func copyInstallFile(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // G304: src is this process's executable or a staged credential
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) //nolint:gosec // G302: dest is the staging file, mode is 0755 or 0600
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// replaceFile moves src onto dest. Windows refuses a rename over an existing
// file, so the previous file is moved aside and restored if the new name fails.
func replaceFile(src, dest string) error {
	if err := os.Rename(src, dest); err == nil { //nolint:gosec // G703: both paths are install paths chosen by this process
		return nil
	}
	backup := dest + ".bak"
	_ = os.Remove(backup)
	if err := os.Rename(dest, backup); err != nil { //nolint:gosec // G703: dest is the install path
		return err
	}
	if err := os.Rename(src, dest); err != nil { //nolint:gosec // G703: src is the staged file
		_ = os.Rename(backup, dest)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func retargetStagedConfig(body []byte, staging, live string) ([]byte, error) {
	// Compare decoded paths. On Windows a staging path is written into JSON
	// with escaped backslashes, so it is not a substring of the raw text.
	// filepath.Dir also uses the host separator, which does not split a
	// Windows path when this function is tested on macOS or Linux.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var probe map[string]any
	if err := dec.Decode(&probe); err != nil {
		return nil, err
	}
	stageDir := parseInstallPath(staging)
	changed := false
	for _, it := range stagedCredentialFiles {
		raw, ok := probe[it.key]
		if !ok || raw == nil {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		parsed := parseInstallPath(s)
		if !sameInstallDir(installParent(parsed), stageDir) {
			continue
		}
		base := installBase(parsed)
		if base == "" {
			continue
		}
		probe[it.key] = joinInstallPath(live, base)
		changed = true
	}
	if !changed {
		return body, nil
	}
	out, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// isWindowsInstallPath reports a path whose separator or volume is Windows
// syntax, including when this process is not running on Windows.
func isWindowsInstallPath(p string) bool {
	if strings.Contains(p, `\`) {
		return true
	}
	return len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0])
}

func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

type installPathParts struct {
	windows bool
	volume  string
	elems   []string
}

func parseInstallPath(p string) installPathParts {
	if isWindowsInstallPath(p) {
		return parseWindowsInstallPath(p)
	}
	clean := filepath.Clean(p)
	vol := filepath.VolumeName(clean)
	rest := clean
	if vol != "" {
		rest = strings.TrimPrefix(clean, vol)
	}
	rest = strings.Trim(rest, string(filepath.Separator))
	var elems []string
	if rest != "" && rest != "." {
		elems = strings.Split(rest, string(filepath.Separator))
	}
	return installPathParts{windows: false, volume: vol, elems: elems}
}

func parseWindowsInstallPath(p string) installPathParts {
	p = strings.ReplaceAll(p, `/`, `\`)
	if strings.HasPrefix(p, `\\`) {
		parts := cleanInstallElems(strings.Split(strings.TrimPrefix(p, `\\`), `\`))
		if len(parts) >= 2 {
			return installPathParts{
				windows: true,
				volume:  `\\` + parts[0] + `\` + parts[1],
				elems:   parts[2:],
			}
		}
		return installPathParts{windows: true, volume: p}
	}
	vol := ""
	rest := p
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		vol = p[:2]
		rest = p[2:]
	}
	return installPathParts{
		windows: true,
		volume:  vol,
		elems:   cleanInstallElems(strings.Split(rest, `\`)),
	}
}

func cleanInstallElems(in []string) []string {
	var out []string
	for _, e := range in {
		if e == "" || e == "." {
			continue
		}
		if e == ".." && len(out) > 0 {
			out = out[:len(out)-1]
			continue
		}
		out = append(out, e)
	}
	return out
}

func installParent(p installPathParts) installPathParts {
	if len(p.elems) == 0 {
		return p
	}
	parent := p
	parent.elems = append([]string(nil), p.elems[:len(p.elems)-1]...)
	return parent
}

func installBase(p installPathParts) string {
	if len(p.elems) == 0 {
		return ""
	}
	return p.elems[len(p.elems)-1]
}

func sameInstallDir(a, b installPathParts) bool {
	if a.windows != b.windows {
		return false
	}
	if a.windows {
		if !strings.EqualFold(a.volume, b.volume) {
			return false
		}
	} else if a.volume != b.volume {
		return false
	}
	if len(a.elems) != len(b.elems) {
		return false
	}
	for i := range a.elems {
		if a.windows {
			if !strings.EqualFold(a.elems[i], b.elems[i]) {
				return false
			}
			continue
		}
		if a.elems[i] != b.elems[i] {
			return false
		}
	}
	return true
}

func joinInstallPath(dir, base string) string {
	if isWindowsInstallPath(dir) {
		dir = strings.TrimRight(strings.ReplaceAll(dir, `/`, `\`), `\`)
		return dir + `\` + base
	}
	return filepath.Join(dir, base)
}

// waitWindowsImageExit polls tasklist until image has no process left, or
// until the only process left is selfPID. selfPID 0 waits for none.
func waitWindowsImageExit(image string, selfPID int) error {
	deadline := windowsNow().Add(windowsExitWait)
	for {
		out, err := runServiceCommand("tasklist", "/FI", "IMAGENAME eq "+image, "/FO", "CSV", "/NH")
		text := string(out)
		pids := tasklistPIDs(text)
		noMatch := strings.Contains(strings.ToLower(text), "no tasks are running")
		if (err == nil || noMatch) && windowsImageClear(pids, selfPID) {
			return nil
		}
		if !windowsNow().Before(deadline) {
			return fmt.Errorf("timed out waiting for %s to exit", image)
		}
		windowsSleep(windowsPollGap)
	}
}

func windowsImageClear(pids []int, selfPID int) bool {
	for _, pid := range pids {
		if selfPID == 0 || pid != selfPID {
			return false
		}
	}
	return true
}

func tasklistPIDs(out string) []int {
	var pids []int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.Trim(fields[1], `"`))
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}
