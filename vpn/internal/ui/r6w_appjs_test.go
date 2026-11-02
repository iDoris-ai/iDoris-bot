package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// r6wRunAppJS runs script against the real app.js in a Node vm, the same
// harness as TestR5WAppJSSameRoleReplacementIsNotSuccess.
func r6wRunAppJS(t *testing.T, script string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	app, err := os.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	smoke := filepath.Join(dir, "smoke.mjs")
	if err := os.WriteFile(smoke, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), app, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, smoke)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node smoke: %v\n%s", err, out)
	}
}

// TestR6WAppJSCanonicalControlURL is the page half of a re-apply whose pin
// and discovery URL differ only by spelling. The daemon reports the pinned
// spelling. Equivalent URLs must finish the poll; a different host must not.
func TestR6WAppJSCanonicalControlURL(t *testing.T) {
	r6wRunAppJS(t, r6wAppJSCanonicalSmoke)
}

const r6wAppJSCanonicalSmoke = `import { readFileSync } from "node:fs";
import vm from "node:vm";

const elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id, value: "", checked: false, textContent: "", disabled: false, listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      classList: { add() {}, remove() {} },
    };
  }
  return elements[id];
}
let applyBody = null;
let statusQueue = [];
let statusHold = null;
const timers = [];
const fetch = async (url) => {
  if (url === "/api/apply") {
    return { ok: true, status: 200, text: async () => JSON.stringify(applyBody) };
  }
  if (url === "/api/status") {
    const st = statusQueue.length ? statusQueue.shift() : statusHold;
    return { ok: true, status: 200, json: async () => st, text: async () => JSON.stringify(st) };
  }
  return { ok: true, status: 200, text: async () => "{}" };
};
const document = { getElementById: el, querySelector() { return null; } };
const context = {
  document, fetch, Promise, JSON, Error, Object,
  sessionStorage: { getItem() { return null; }, setItem() {} },
  location: { hash: "", pathname: "/", search: "" },
  history: { replaceState() {} },
  window: {},
  console,
  setTimeout(fn, ms) { timers.push(fn); return timers.length; },
};
context.window.history = context.history;
context.window.location = context.location;
context.window.setTimeout = context.setTimeout;
vm.createContext(context);
vm.runInContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), context);

async function flush() {
  await new Promise((r) => setTimeout(r, 20));
}
async function enable(discoveryURL, reportedURL) {
  timers.length = 0;
  applyBody = {
    config_path: "/home/acme/.idoris/vpn.json",
    role: "member", hostname: "laptop", enroll_url: "https://enroll.example",
    control_url: "",
    discovery_control_url: discoveryURL,
    service_installed: true
  };
  const st = { phase: "connected", role: "member", control_url: reportedURL };
  statusQueue = [st];
  statusHold = st;
  el("confirm-authority").checked = true;
  el("enable").listeners.click();
  await flush();
}
function statusText() { return el("status").textContent; }

await flush();
await enable("https://vpn.example.org", "https://other.example.org");
if (!statusText().includes("上一份身份")) {
  throw new Error("different host looked done: " + statusText());
}
if (timers.length < 1) throw new Error("different host stopped polling");

await enable("https://vpn.example.org", "https://vpn.example.org/");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("trailing slash on the daemon URL did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org/", "https://vpn.example.org");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("trailing slash on the expected URL did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org", "HTTPS://VPN.Example.org");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("upper-case scheme or host did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org", "https://vpn.example.org:443");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("explicit :443 did not match: " + statusText() + " timers " + timers.length);
}
await enable("http://vpn.example.org/x", "http://vpn.example.org:80/x/");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("explicit :80 or path slash did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org", "HTTPS://VPN.Example.org:443/");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("combined case, port, and slash did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org/headscale", "https://vpn.example.org/headscale/?x=1#frag");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("query, fragment, or path slash did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://login.tailscale.com", "https://controlplane.tailscale.com");
if (statusText().includes("上一份身份") || timers.length !== 0) {
  throw new Error("tailscale login synonyms did not match: " + statusText() + " timers " + timers.length);
}
await enable("https://vpn.example.org", "https://vpn.example.org:8443");
if (!statusText().includes("上一份身份") || timers.length < 1) {
  throw new Error("non-default port looked done: " + statusText());
}
console.log("ok");
`

// TestR6WAppJSUnconfirmedIdentityIsNotDone is a replacement whose configured
// fingerprint already matches, while the daemon has not confirmed it.
// identity_unconfirmed true keeps the page polling and shows the daemon's
// own warning. The same status without the key completes, including when a
// later poll clears the key. A stuck flag eventually fails in the open.
func TestR6WAppJSUnconfirmedIdentityIsNotDone(t *testing.T) {
	r6wRunAppJS(t, r6wAppJSUnconfirmedSmoke)
}

const r6wAppJSUnconfirmedSmoke = `import { readFileSync } from "node:fs";
import vm from "node:vm";

const elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id, value: "", checked: false, textContent: "", disabled: false, listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      classList: { add() {}, remove() {} },
    };
  }
  return elements[id];
}
const unreachable = "enrollment service is unreachable; continuing with the saved control URL and the existing node identity. A new login is attempted only when this node actually needs one";
const notConfirmed = "discovery failed and the saved enrollment identity is not confirmed for this token; access stays closed until discovery succeeds";
function matching(flag) {
  const st = {
    phase: "connected",
    role: "member",
    control_url: "https://hs.example",
    tenant: "acme",
    token_fingerprint: "fp-b",
    warnings: [unreachable, notConfirmed],
    last_error: notConfirmed
  };
  if (flag) st.identity_unconfirmed = true;
  return st;
}
let applyBody = null;
let statusQueue = [];
let statusHold = null;
const timers = [];
const fetch = async (url) => {
  if (url === "/api/apply") {
    return { ok: true, status: 200, text: async () => JSON.stringify(applyBody) };
  }
  if (url === "/api/status") {
    const st = statusQueue.length ? statusQueue.shift() : statusHold;
    return { ok: true, status: 200, json: async () => st, text: async () => JSON.stringify(st) };
  }
  return { ok: true, status: 200, text: async () => "{}" };
};
const document = { getElementById: el, querySelector() { return null; } };
const context = {
  document, fetch, Promise, JSON, Error, Object,
  sessionStorage: { getItem() { return null; }, setItem() {} },
  location: { hash: "", pathname: "/", search: "" },
  history: { replaceState() {} },
  window: {},
  console,
  setTimeout(fn, ms) { timers.push(fn); return timers.length; },
};
context.window.history = context.history;
context.window.location = context.location;
context.window.setTimeout = context.setTimeout;
vm.createContext(context);
vm.runInContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), context);

async function flush() {
  await new Promise((r) => setTimeout(r, 20));
}
function arm(statuses) {
  timers.length = 0;
  applyBody = {
    config_path: "/home/acme/.idoris/vpn.json",
    role: "member", hostname: "laptop", enroll_url: "https://enroll.example",
    control_url: "",
    discovery_control_url: "https://hs.example",
    tenant: "acme",
    token_fingerprint: "fp-b",
    service_installed: true
  };
  statusQueue = statuses.slice();
  statusHold = statuses[statuses.length - 1];
  el("confirm-authority").checked = true;
  el("enable").listeners.click();
}
function text() { return el("status").textContent; }
function assertWaiting() {
  if (!text().includes("身份尚未确认") || !text().includes(unreachable) || !text().includes(notConfirmed)) {
    throw new Error("unconfirmed wait hid the daemon warning: " + text());
  }
  if (text().includes("等待超时")) throw new Error("still-polling status already says timed out: " + text());
  if (timers.length < 1) throw new Error("unconfirmed status looked complete: " + text());
}
function assertDone(why) {
  if (text().includes("身份尚未确认") || text().includes("上一份身份") || text().includes("等待超时")) {
    throw new Error(why + ": " + text());
  }
  if (timers.length !== 0) throw new Error(why + " kept polling");
}

await flush();
arm([matching(true)]);
await flush();
assertWaiting();

arm([matching(false)]);
await flush();
assertDone("the same status without identity_unconfirmed");

arm([matching(true), matching(false)]);
await flush();
assertWaiting();
const pending = timers.length;
if (timers.length < 1) throw new Error("poll stopped before the flag cleared");
timers.shift()();
await flush();
if (timers.length !== pending - 1) throw new Error("poll continued after the flag cleared");
assertDone("flag cleared on a later poll");

arm([matching(true)]);
await flush();
assertWaiting();
let steps = 0;
while (timers.length > 0 && steps < 200) {
  timers.shift()();
  await flush();
  steps++;
  if (text().includes("等待超时") && timers.length === 0) break;
}
if (!text().includes("等待超时") || !text().includes("身份尚未确认")) {
  throw new Error("timeout did not name the unconfirmed identity after " + steps + ": " + text());
}
if (!text().includes(unreachable) || !text().includes(notConfirmed)) {
  throw new Error("timeout dropped the daemon warning: " + text());
}
if (timers.length !== 0) throw new Error("poll continued after the unconfirmed timeout");
if (steps < 2) throw new Error("unconfirmed poll timed out immediately");
console.log("ok steps " + steps);
`
