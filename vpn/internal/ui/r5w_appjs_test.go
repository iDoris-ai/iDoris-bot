package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestR5WAppJSSameRoleReplacementIsNotSuccess is the page half of a
// same-role enrollment replacement. The apply result has an empty written
// pin and a discovery control URL. A daemon that is already connected as
// the same role on the previous server must keep the page polling.
func TestR5WAppJSSameRoleReplacementIsNotSuccess(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	app, err := os.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "smoke.mjs")
	if err := os.WriteFile(script, []byte(r5wAppJSSameRoleSmoke), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), app, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node smoke: %v\n%s", err, out)
	}
}

const r5wAppJSSameRoleSmoke = `import { readFileSync } from "node:fs";
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
let statuses = 0;
const timers = [];
const fetch = async (url) => {
  if (url === "/api/apply") {
    return { ok: true, status: 200, text: async () => JSON.stringify({
      config_path: "/home/acme/.idoris/vpn.json",
      role: "member", hostname: "laptop", enroll_url: "https://b.example",
      control_url: "",
      discovery_control_url: "https://hs-b.example",
      tenant: "beta",
      token_fingerprint: "fp-b",
      control_pin_dropped: true,
      service_installed: true
    }) };
  }
  if (url === "/api/status") {
    statuses++;
    const seq = [
      { phase: "connected", role: "member", control_url: "https://hs-a.example" },
      { phase: "connected", role: "member", control_url: "https://hs-b.example", tenant: "old" },
      { phase: "connected", role: "member", control_url: "https://hs-b.example", tenant: "beta", token_fingerprint: "fp-old" },
      { phase: "connected", role: "member", control_url: "https://hs-b.example", tenant: "beta", token_fingerprint: "fp-b" },
    ];
    const st = seq[Math.min(statuses, seq.length) - 1];
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
await new Promise((r) => setTimeout(r, 20));
el("confirm-authority").checked = true;
el("enable").listeners.click();
await new Promise((r) => setTimeout(r, 30));
const result = el("result").textContent;
if (!result.includes("控制服务器：https://hs-b.example") || !result.includes("租户：beta")) {
  throw new Error("result did not name the applied server: " + result);
}
if (!el("status").textContent.includes("上一份身份")) {
  throw new Error("old same-role daemon was treated as success: " + el("status").textContent);
}
function step() {
  if (timers.length < 1) throw new Error("poll stopped before the applied identity");
  timers.shift()();
}
await new Promise((r) => setTimeout(r, 20));
step();
await new Promise((r) => setTimeout(r, 20));
if (!el("status").textContent.includes("上一份身份")) {
  throw new Error("wrong tenant looked done: " + el("status").textContent);
}
step();
await new Promise((r) => setTimeout(r, 20));
if (!el("status").textContent.includes("上一份身份")) {
  throw new Error("wrong fingerprint looked done: " + el("status").textContent);
}
const pending = timers.length;
step();
await new Promise((r) => setTimeout(r, 20));
if (el("status").textContent.includes("上一份身份")) {
  throw new Error("matching identity still looks old: " + el("status").textContent);
}
if (timers.length !== pending - 1) {
  throw new Error("poll continued after the applied identity");
}
console.log("ok");
`
