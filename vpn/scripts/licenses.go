//go:build vpnlicenses

// Command licenses checks third-party licenses for the binaries under ./cmd
// and writes THIRD_PARTY_NOTICES.md.
//
// Run from the vpn module directory:
//
//	go run -tags vpnlicenses ./scripts/licenses.go check
//	go run -tags vpnlicenses ./scripts/licenses.go notices
//
// The allowlist lives in allowedLicenses. Extending it is a legal decision:
// read the license, confirm it can ship inside this Apache-2.0 product, then
// add the SPDX name. Do not add GPL, AGPL, LGPL, MPL, CC, or Unknown.
// Regenerate THIRD_PARTY_NOTICES.md in the same change.
//
// VPN_LICENSES_PROBE_DIR, when set, is an extra module directory checked with
// the same allowlist before the real binaries. It can only add a failure.
// It does not skip ./cmd when the probe passes, and it cannot widen the
// allowlist.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	// Pinned release on the module path `go run` was asked to use.
	// v1.6.0 is the latest tag of github.com/google/go-licenses (v2 moved
	// to a /v2 module path) and it has --allowed_licenses.
	goLicensesModule = "github.com/google/go-licenses@v1.6.0"

	ownModule   = "github.com/iDoris-ai/iDoris-bridge/vpn"
	noticesName = "THIRD_PARTY_NOTICES.md"

	recordMarker = "@@@IDORIS-LIC-7f3a9c@@@"
	textMarker   = "@@@IDORIS-LIC-TEXT@@@"
)

// allowedLicenses is the only set of SPDX names that may be linked into
// the shipped binaries.
var allowedLicenses = []string{
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"MIT",
	"ISC",
}

// targets is fixed so the notice file does not depend on the host GOARCH.
// The client binary runs on linux, darwin, and windows. amd64 and arm64
// are both scanned because a package can be pulled in by only one of them.
var targets = []target{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

type target struct {
	GOOS   string
	GOARCH string
}

type modID struct {
	Path    string
	Version string
}

type library struct {
	Name        string
	Version     string
	LicenseName string
	LicenseURL  string
	LicensePath string
	Text        string
}

type textEntry struct {
	names []string
	urls  []string
	text  string
}

type modNotice struct {
	id     modID
	goos   map[string]struct{}
	arch   map[string]struct{}
	texts  []textEntry
	notice []textEntry
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "check" && os.Args[1] != "notices") {
		fmt.Fprintf(os.Stderr, "usage: go run -tags vpnlicenses ./scripts/licenses.go check|notices\n")
		os.Exit(2)
	}
	mode := os.Args[1]
	root, err := moduleRoot()
	if err != nil {
		die(err)
	}
	if err := os.Chdir(root); err != nil {
		die(err)
	}

	allow := append([]string(nil), allowedLicenses...)
	sort.Strings(allow)

	// An extra module can only add a failure. It runs first so a deliberate
	// reject does not wait on the full binary scan. A passing probe still
	// falls through into that scan; clearing the variable is the only way
	// to skip it, and that does not weaken the binary check.
	if probe := os.Getenv("VPN_LICENSES_PROBE_DIR"); probe != "" {
		fmt.Fprintf(os.Stderr, "go-licenses probe %s\n", probe)
		if err := runCheck(target{"linux", "amd64"}, probe, []string{"."}, nil, allow); err != nil {
			die(err)
		}
	}

	pkgs := []string{"./cmd/idoris-vpnd", "./cmd/idoris-vpn-enroll"}
	var merged map[modID]*modNotice
	for _, t := range targets {
		fmt.Fprintf(os.Stderr, "go-licenses %s/%s\n", t.GOOS, t.GOARCH)
		var (
			checkErr error
			libs     []library
			libErr   error
			mods     map[string]modMeta
			modErr   error
			wg       sync.WaitGroup
		)
		wg.Add(3)
		go func() {
			defer wg.Done()
			checkErr = runCheck(t, ".", pkgs, []string{ownModule}, allow)
		}()
		go func() {
			defer wg.Done()
			libs, libErr = runReport(t, ".", pkgs, []string{ownModule})
		}()
		go func() {
			defer wg.Done()
			mods, modErr = linkedModules(t, pkgs)
		}()
		wg.Wait()
		if checkErr != nil {
			die(checkErr)
		}
		if libErr != nil {
			die(libErr)
		}
		if modErr != nil {
			die(modErr)
		}
		part, err := assemble(t, mods, libs, allow)
		if err != nil {
			die(fmt.Errorf("%s/%s: %w", t.GOOS, t.GOARCH, err))
		}
		merged = mergeNotices(merged, part)
	}

	body, err := render(allow, merged)
	if err != nil {
		die(err)
	}
	if bytes.Contains(body, []byte(recordMarker)) || bytes.Contains(body, []byte(textMarker)) {
		die(fmt.Errorf("notice output contains an internal marker"))
	}

	switch mode {
	case "notices":
		if err := os.WriteFile(noticesName, body, 0o644); err != nil {
			die(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", noticesName, len(body))
	case "check":
		existing, err := os.ReadFile(noticesName)
		if err != nil {
			die(fmt.Errorf("%s is missing or unreadable (%v); run make notices", noticesName, err))
		}
		if !bytes.Equal(existing, body) {
			diff := unifiedDiff(noticesName, noticesName+".regenerated", existing, body)
			die(fmt.Errorf("%s is stale. Run make notices and commit the result.\n%s", noticesName, diff))
		}
		fmt.Fprintf(os.Stderr, "%s is up to date\n", noticesName)
	}
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(wd, "go.mod")); err != nil {
		return "", fmt.Errorf("run from the vpn module directory (no go.mod in %s)", wd)
	}
	return wd, nil
}

func goBin() string {
	if g := os.Getenv("GO"); g != "" {
		return g
	}
	return "go"
}

// hostEnv is the environment for `go run`. GOOS/GOARCH stay at the host
// values so the go-licenses binary itself is runnable. The target OS is
// applied by an -exec wrapper after that binary has been built.
func hostEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GOOS=") || strings.HasPrefix(e, "GOARCH=") ||
			strings.HasPrefix(e, "CGO_ENABLED=") || strings.HasPrefix(e, "GOFLAGS=") {
			continue
		}
		env = append(env, e)
	}
	return env
}

// writeExecWrapper returns a script `go run -exec` uses to start the
// already-built host binary with the target GOOS/GOARCH. go-licenses has
// no flag for this; it forwards the process environment to `go list`.
func writeExecWrapper(t target, readonly bool) (string, error) {
	f, err := os.CreateTemp("", "idoris-golic-wrap-*.sh")
	if err != nil {
		return "", err
	}
	flags := ""
	if readonly {
		flags = "-mod=readonly"
	}
	script := "#!/bin/sh\n" +
		"export GOOS=" + t.GOOS + "\n" +
		"export GOARCH=" + t.GOARCH + "\n" +
		"export CGO_ENABLED=0\n" +
		"export GO111MODULE=on\n" +
		"export GOFLAGS='" + flags + "'\n" +
		"exec \"$@\"\n"
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func goLicensesCmd(t target, dir string, readonly bool, toolArgs []string) (*exec.Cmd, func(), error) {
	wrap, err := writeExecWrapper(t, readonly)
	if err != nil {
		return nil, nil, err
	}
	args := append([]string{"run", "-exec", wrap, goLicensesModule}, toolArgs...)
	cmd := exec.Command(goBin(), args...)
	cmd.Dir = dir
	cmd.Env = hostEnv()
	cleanup := func() { os.Remove(wrap) }
	return cmd, cleanup, nil
}

func runCheck(t target, dir string, pkgs, ignore, allow []string) error {
	args := []string{
		"check",
		"--allowed_licenses=" + strings.Join(allow, ","),
	}
	for _, prefix := range ignore {
		args = append(args, "--ignore="+prefix)
	}
	args = append(args, pkgs...)
	cmd, cleanup, err := goLicensesCmd(t, dir, dir == ".", args)
	if err != nil {
		return err
	}
	defer cleanup()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return nil
	}
	msg := licenseErrors(stderr.String())
	if msg == "" {
		msg = redact(stderr.String())
		if strings.TrimSpace(stdout.String()) != "" {
			msg += "\n" + redact(stdout.String())
		}
	}
	return fmt.Errorf("license check failed for GOOS=%s GOARCH=%s (allowlist: %s)\n%s",
		t.GOOS, t.GOARCH, strings.Join(allow, ", "), strings.TrimSpace(msg))
}

// licenseErrors keeps the lines that name the offending package and drops
// go-licenses noise (absolute module-cache paths, klog timestamps).
func licenseErrors(stderr string) string {
	var keep []string
	for _, line := range strings.Split(stderr, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if strings.Contains(l, "Not allowed license") ||
			strings.Contains(l, "Did not find license") ||
			strings.Contains(l, "not allowed license type") ||
			strings.Contains(l, "Error identifying license") {
			keep = append(keep, redact(l))
		}
	}
	return strings.Join(keep, "\n")
}

func runReport(t target, dir string, pkgs, ignore []string) ([]library, error) {
	tmpl, err := os.CreateTemp("", "idoris-lic-tmpl-*.txt")
	if err != nil {
		return nil, err
	}
	tmplPath := tmpl.Name()
	defer os.Remove(tmplPath)
	template := "" +
		"{{range .}}" + recordMarker + "\n" +
		"{{.Name}}\n{{.Version}}\n{{.LicenseName}}\n{{.LicenseURL}}\n{{.LicensePath}}\n" +
		textMarker + "\n" +
		"{{.LicenseText}}{{end}}\n"
	if _, err := tmpl.WriteString(template); err != nil {
		tmpl.Close()
		return nil, err
	}
	if err := tmpl.Close(); err != nil {
		return nil, err
	}

	args := []string{"report", "--template=" + tmplPath}
	for _, prefix := range ignore {
		args = append(args, "--ignore="+prefix)
	}
	args = append(args, pkgs...)
	cmd, cleanup, err := goLicensesCmd(t, dir, true, args)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go-licenses report %s/%s: %w\n%s", t.GOOS, t.GOARCH, err, redact(stderr.String()))
	}
	if bytes.Contains(stdout.Bytes(), []byte(recordMarker)) && strings.Contains(stdout.String(), textMarker) {
		// parsed below
	}
	libs, err := parseReport(stdout.String())
	if err != nil {
		return nil, fmt.Errorf("parse report %s/%s: %w", t.GOOS, t.GOARCH, err)
	}
	return libs, nil
}

func parseReport(out string) ([]library, error) {
	if !strings.Contains(out, recordMarker) {
		if strings.TrimSpace(out) == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("report has no records")
	}
	parts := strings.Split(out, recordMarker)
	var libs []library
	for _, part := range parts[1:] {
		part = strings.TrimPrefix(part, "\n")
		head, text, ok := strings.Cut(part, textMarker+"\n")
		if !ok {
			return nil, fmt.Errorf("record missing license text marker")
		}
		lines := strings.Split(strings.TrimSuffix(head, "\n"), "\n")
		if len(lines) != 5 {
			return nil, fmt.Errorf("record header has %d lines, want 5", len(lines))
		}
		if strings.Contains(text, recordMarker) || strings.Contains(text, textMarker) {
			return nil, fmt.Errorf("license text for %s contains an internal marker; refusing to guess a boundary", lines[0])
		}
		libs = append(libs, library{
			Name:        lines[0],
			Version:     lines[1],
			LicenseName: lines[2],
			LicenseURL:  lines[3],
			LicensePath: lines[4],
			Text:        normalizeNewlines(text),
		})
	}
	return libs, nil
}

type listedPkg struct {
	ImportPath string
	Standard   bool
	Module     *struct {
		Path    string
		Version string
		Main    bool
		Origin  *struct {
			URL string
		}
	}
}

func linkedModules(t target, pkgs []string) (map[string]modMeta, error) {
	args := append([]string{"list", "-deps", "-json"}, pkgs...)
	cmd := exec.Command(goBin(), args...)
	cmd.Env = append(hostEnv(),
		"GOOS="+t.GOOS,
		"GOARCH="+t.GOARCH,
		"CGO_ENABLED=0",
		"GOFLAGS=-mod=readonly",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list %s/%s: %w\n%s", t.GOOS, t.GOARCH, err, redact(stderr.String()))
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	out := map[string]modMeta{}
	for dec.More() {
		var p listedPkg
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		if p.Standard || p.Module == nil || p.Module.Main {
			continue
		}
		if p.Module.Path == ownModule || strings.HasPrefix(p.Module.Path, ownModule+"/") {
			continue
		}
		meta := out[p.Module.Path]
		if meta.Version == "" {
			meta.Version = p.Module.Version
			meta.Source = sourceURL(p.Module.Path, "")
		}
		if meta.Version != p.Module.Version {
			return nil, fmt.Errorf("module %s has versions %s and %s", p.Module.Path, meta.Version, p.Module.Version)
		}
		if p.Module.Origin != nil {
			if u := httpURL(p.Module.Origin.URL); u != "" && meta.Source == "" {
				meta.Source = u
			}
		}
		if meta.Source == "" {
			meta.Source = sourceURL(p.Module.Path, "")
		}
		out[p.Module.Path] = meta
	}
	return out, nil
}

type modMeta struct {
	Version string
	Source  string
}

func assemble(t target, mods map[string]modMeta, libs []library, allow []string) (map[modID]*modNotice, error) {
	allowed := map[string]struct{}{}
	for _, name := range allow {
		allowed[name] = struct{}{}
	}
	byPath := map[string]*modNotice{}
	seenLib := map[string]struct{}{}

	for _, lib := range libs {
		if lib.Name == ownModule || strings.HasPrefix(lib.Name, ownModule+"/") {
			continue
		}
		path, meta, ok := matchModule(lib, mods)
		if !ok {
			return nil, fmt.Errorf("license library %s is not in the linked module set", lib.Name)
		}
		name := lib.LicenseName
		if name == "" || name == "Unknown" {
			return nil, fmt.Errorf("no allowed license name for package %s (module %s)", lib.Name, path)
		}
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("not allowed license %q for package %s (module %s)", name, lib.Name, path)
		}
		text := strings.TrimRight(lib.Text, "\n")
		if strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("empty license text for package %s (module %s)", lib.Name, path)
		}
		text += "\n"
		id := modID{Path: path, Version: meta.Version}
		n := byPath[path]
		if n == nil {
			n = &modNotice{id: id, goos: map[string]struct{}{}, arch: map[string]struct{}{}}
			byPath[path] = n
		}
		if n.id.Version != id.Version {
			return nil, fmt.Errorf("module %s versions disagree: %s vs %s", path, n.id.Version, id.Version)
		}
		n.goos[t.GOOS] = struct{}{}
		n.arch[t.GOARCH] = struct{}{}
		url := httpURL(lib.LicenseURL)
		if url == "" {
			url = meta.Source
		}
		n.addText(name, url, text)
		if err := n.addNotices(lib.LicensePath); err != nil {
			return nil, err
		}
		seenLib[path] = struct{}{}
	}

	for path, meta := range mods {
		if _, ok := seenLib[path]; ok {
			continue
		}
		return nil, fmt.Errorf("module %s@%s is linked into the binary but go-licenses reported no license", path, meta.Version)
	}

	out := make(map[modID]*modNotice, len(byPath))
	for _, n := range byPath {
		out[n.id] = n
	}
	return out, nil
}

func (n *modNotice) addText(name, url, text string) {
	for i := range n.texts {
		if n.texts[i].text == text {
			n.texts[i].names = appendUnique(n.texts[i].names, name)
			if url != "" {
				n.texts[i].urls = appendUnique(n.texts[i].urls, url)
			}
			return
		}
	}
	e := textEntry{text: text}
	e.names = appendUnique(nil, name)
	if url != "" {
		e.urls = appendUnique(nil, url)
	}
	n.texts = append(n.texts, e)
}

func (n *modNotice) addNotices(licensePath string) error {
	if licensePath == "" || licensePath == "Unknown" {
		return nil
	}
	if !filepath.IsAbs(licensePath) {
		return fmt.Errorf("license path for %s is not absolute; refusing to read it", n.id.Path)
	}
	dir := filepath.Dir(licensePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read license directory for %s: %w", n.id.Path, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		base := e.Name()
		upper := strings.ToUpper(base)
		if upper == "NOTICE" || upper == "NOTICE.TXT" || upper == "NOTICE.MD" {
			names = append(names, base)
		}
	}
	sort.Strings(names)
	for _, base := range names {
		b, err := os.ReadFile(filepath.Join(dir, base))
		if err != nil {
			return fmt.Errorf("read NOTICE for %s: %w", n.id.Path, err)
		}
		text := normalizeNewlines(string(b))
		if strings.TrimSpace(text) == "" {
			continue
		}
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		dup := false
		for _, existing := range n.notice {
			if existing.text == text {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		n.notice = append(n.notice, textEntry{names: []string{base}, text: text})
	}
	return nil
}

func matchModule(lib library, mods map[string]modMeta) (string, modMeta, bool) {
	best := ""
	for path := range mods {
		if lib.Name == path || strings.HasPrefix(lib.Name, path+"/") {
			if len(path) > len(best) {
				best = path
			}
		}
	}
	if best == "" {
		return "", modMeta{}, false
	}
	return best, mods[best], true
}

func mergeNotices(dst, src map[modID]*modNotice) map[modID]*modNotice {
	if dst == nil {
		dst = map[modID]*modNotice{}
	}
	for id, n := range src {
		have := dst[id]
		if have == nil {
			dst[id] = n
			continue
		}
		for g := range n.goos {
			have.goos[g] = struct{}{}
		}
		for a := range n.arch {
			have.arch[a] = struct{}{}
		}
		for _, e := range n.texts {
			for _, name := range e.names {
				url := ""
				if len(e.urls) > 0 {
					url = e.urls[0]
				}
				have.addText(name, url, e.text)
				for _, u := range e.urls {
					have.addText(name, u, e.text)
				}
			}
		}
		for _, e := range n.notice {
			dup := false
			for _, existing := range have.notice {
				if existing.text == e.text {
					dup = true
					break
				}
			}
			if !dup {
				have.notice = append(have.notice, e)
			}
		}
	}
	return dst
}

func render(allow []string, mods map[modID]*modNotice) ([]byte, error) {
	ids := make([]modID, 0, len(mods))
	for id := range mods {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Path != ids[j].Path {
			return ids[i].Path < ids[j].Path
		}
		return ids[i].Version < ids[j].Version
	})

	var b strings.Builder
	b.WriteString("# Third-party notices\n\n")
	b.WriteString("This file lists every third-party Go module linked into the binaries\n")
	b.WriteString("this repository ships from `vpn/cmd`: `idoris-vpnd` and `idoris-vpn-enroll`.\n")
	b.WriteString("The scan is `go list -deps` of those two packages (not tests) for\n")
	b.WriteString("`GOOS` in linux, darwin, and windows, and `GOARCH` in amd64 and arm64,\n")
	b.WriteString("with `CGO_ENABLED=0`. Each module is named with the version that is\n")
	b.WriteString("linked, the SPDX license name reported by go-licenses, a source URL\n")
	b.WriteString("when one can be derived, and the full license text. Identical license\n")
	b.WriteString("texts inside one module appear once.\n\n")
	b.WriteString("Generated by `make notices` via `go run " + goLicensesModule + "`.\n")
	b.WriteString("There is no timestamp and no machine path in this file.\n")
	b.WriteString("`make licenses` fails if this file does not match a fresh run.\n\n")
	b.WriteString("Allowlist: " + strings.Join(allow, ", ") + ".\n")
	b.WriteString("Anything else, including GPL, AGPL, LGPL, MPL, CC, and unknown\n")
	b.WriteString("licenses, fails the build. Adding a name to the allowlist needs\n")
	b.WriteString("human review; see the comment on the `licenses` target in the Makefile.\n\n")
	b.WriteString("This repository does not redistribute the Tailscale client, Headscale,\n")
	b.WriteString("or Headplane. Members install the official Tailscale client themselves.\n")
	b.WriteString("Headscale and Headplane, when deployed, are upstream programs run from\n")
	b.WriteString("their own images. Their license terms are not the notices below.\n\n")
	b.WriteString("go-licenses does not list the Go standard library. The runtime compiled\n")
	b.WriteString("into both binaries is covered by the Go license (BSD-3-Clause):\n")
	b.WriteString("https://go.dev/LICENSE. Reproduce that notice with any distribution\n")
	b.WriteString("of the binaries.\n\n")
	b.WriteString(fmt.Sprintf("Modules: %d\n\n", len(ids)))
	b.WriteString("## Modules\n\n")
	b.WriteString("| Module | Version | License | Source | GOOS |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, id := range ids {
		n := mods[id]
		names := licenseNames(n)
		src := firstURL(n)
		b.WriteString("| `")
		b.WriteString(cell(id.Path))
		b.WriteString("` | `")
		b.WriteString(cell(id.Version))
		b.WriteString("` | ")
		b.WriteString(cell(strings.Join(names, ", ")))
		b.WriteString(" | ")
		b.WriteString(cell(src))
		b.WriteString(" | ")
		b.WriteString(cell(joinKeys(n.goos)))
		b.WriteString(" |\n")
	}
	b.WriteString("\n## License texts\n\n")
	for _, id := range ids {
		n := mods[id]
		fmt.Fprintf(&b, "### `%s` `%s`\n\n", id.Path, id.Version)
		texts := append([]textEntry(nil), n.texts...)
		sort.Slice(texts, func(i, j int) bool {
			ni := strings.Join(sortedCopy(texts[i].names), ",")
			nj := strings.Join(sortedCopy(texts[j].names), ",")
			if ni != nj {
				return ni < nj
			}
			return texts[i].text < texts[j].text
		})
		for _, e := range texts {
			names := sortedCopy(e.names)
			urls := sortedCopy(e.urls)
			b.WriteString("- License: " + strings.Join(names, ", ") + "\n")
			if len(urls) == 0 {
				b.WriteString("- Source: not derivable\n")
			} else {
				for _, u := range urls {
					b.WriteString("- Source: " + u + "\n")
				}
			}
			b.WriteString("\n")
			writeFence(&b, e.text)
			b.WriteString("\n")
		}
		if len(n.notice) > 0 {
			notices := append([]textEntry(nil), n.notice...)
			sort.Slice(notices, func(i, j int) bool { return notices[i].text < notices[j].text })
			b.WriteString("NOTICE files next to the license file are included because Apache-2.0\n")
			b.WriteString("requires them to travel with a distribution that contains the work.\n\n")
			for _, e := range notices {
				b.WriteString("#### NOTICE\n\n")
				writeFence(&b, e.text)
				b.WriteString("\n")
			}
		}
	}
	out := []byte(b.String())
	if bytes.Contains(out, []byte("/Users/")) || bytes.Contains(out, []byte("/home/")) || bytes.Contains(out, []byte(`\Users\`)) {
		return nil, fmt.Errorf("refusing to write notices that contain a home directory path")
	}
	return out, nil
}

func licenseNames(n *modNotice) []string {
	var names []string
	for _, e := range n.texts {
		for _, name := range e.names {
			names = appendUnique(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func firstURL(n *modNotice) string {
	var urls []string
	for _, e := range n.texts {
		urls = append(urls, e.urls...)
	}
	sort.Strings(urls)
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func writeFence(b *strings.Builder, text string) {
	n := 3
	run := 0
	for _, r := range text {
		if r == '`' {
			run++
			if run >= n {
				n = run + 1
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", n)
	b.WriteString(fence + "\n")
	b.WriteString(text)
	if !strings.HasSuffix(text, "\n") {
		b.WriteString("\n")
	}
	b.WriteString(fence + "\n")
}

func joinKeys(set map[string]struct{}) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func appendUnique(in []string, v string) []string {
	for _, have := range in {
		if have == v {
			return in
		}
	}
	return append(in, v)
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func httpURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "Unknown" || strings.Contains(raw, " ") {
		return ""
	}
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return raw
	}
	return ""
}

func sourceURL(modulePath, origin string) string {
	if u := httpURL(origin); u != "" {
		return strings.TrimSuffix(u, ".git")
	}
	parts := strings.Split(modulePath, "/")
	switch {
	case len(parts) >= 3 && parts[0] == "github.com":
		return "https://github.com/" + parts[1] + "/" + parts[2]
	case len(parts) >= 3 && parts[0] == "golang.org" && parts[1] == "x":
		return "https://cs.opensource.google/go/x/" + parts[2]
	default:
		return ""
	}
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func redact(s string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		s = strings.ReplaceAll(s, home, "$HOME")
	}
	return s
}

func unifiedDiff(oldName, newName string, oldBody, newBody []byte) string {
	oldFile, err := os.CreateTemp("", "idoris-lic-old-*")
	if err != nil {
		return "(diff unavailable: " + err.Error() + ")"
	}
	newFile, err := os.CreateTemp("", "idoris-lic-new-*")
	if err != nil {
		os.Remove(oldFile.Name())
		return "(diff unavailable: " + err.Error() + ")"
	}
	defer os.Remove(oldFile.Name())
	defer os.Remove(newFile.Name())
	if _, err := oldFile.Write(oldBody); err != nil {
		return "(diff unavailable)"
	}
	if _, err := newFile.Write(newBody); err != nil {
		return "(diff unavailable)"
	}
	oldFile.Close()
	newFile.Close()
	cmd := exec.Command("diff", "-u", oldFile.Name(), newFile.Name())
	out, _ := cmd.Output()
	text := string(out)
	text = strings.ReplaceAll(text, oldFile.Name(), oldName)
	text = strings.ReplaceAll(text, newFile.Name(), newName)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		text = strings.ReplaceAll(text, home, "$HOME")
	}
	if len(text) > 8000 {
		text = text[:8000] + "\n... diff truncated ...\n"
	}
	return text
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "licenses: %s\n", err)
	os.Exit(1)
}
