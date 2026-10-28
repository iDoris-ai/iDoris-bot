package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestR4WAppJSWaitsForTheNewIdentity(t *testing.T) {
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
	if err := os.WriteFile(script, []byte(r4wAppJSIdentitySmoke), 0o600); err != nil {
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

func TestR4WAppJSHidesGatewayQuestionsForMember(t *testing.T) {
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
	if err := os.WriteFile(script, []byte(r4wAppJSMemberSmoke), 0o600); err != nil {
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

func TestR4WAppJSClearsConfirmationWhenSaving(t *testing.T) {
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
	if err := os.WriteFile(script, []byte(r4wAppJSConfirmSmoke), 0o600); err != nil {
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

const r4wAppJSIdentitySmoke = `import { readFileSync } from "node:fs";
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
      service_installed: true
    }) };
  }
  if (url === "/api/status") {
    statuses++;
    const st = statuses === 1
      ? { phase: "connected", role: "gateway", control_url: "https://hs-a.example" }
      : { phase: "connected", role: "member" };
    return { ok: true, status: 200, json: async () => st, text: async () => JSON.stringify(st) };
  }
  return { ok: true, status: 200, text: async () => "{}" };
};
const document = { getElementById: el, querySelector() { return null; } };
const context = {
  document, fetch, Promise, JSON, Error,
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
if (!result.includes("https://b.example") || !result.includes("member") || !result.includes("服务已按这份新身份安装")) {
  throw new Error("result " + result);
}
if (!el("status").textContent.includes("上一份身份")) {
  throw new Error("old identity was treated as success: " + el("status").textContent);
}
if (timers.length < 1) throw new Error("poll stopped on the previous identity");
const pending = timers.length;
timers.shift()();
await new Promise((r) => setTimeout(r, 30));
if (el("status").textContent.includes("上一份身份")) {
  throw new Error("matching identity still looks old: " + el("status").textContent);
}
if (timers.length !== pending - 1) throw new Error("poll continued after the new identity");
console.log("ok");
`

const r4wAppJSConfirmSmoke = `import { readFileSync } from "node:fs";
import vm from "node:vm";

const elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id,
      value: "",
      checked: false,
      textContent: "",
      disabled: false,
      listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      classList: { add() {}, remove() {} },
    };
  }
  return elements[id];
}
const calls = [];
const fetch = async (url, opt) => {
  calls.push({ url, body: opt && opt.body ? JSON.parse(opt.body) : null });
  if (url === "/api/bootstrap") {
    return { ok: true, status: 200, text: async () => JSON.stringify({ capability: "cap-1", csrf: "csrf-1" }) };
  }
  if (url === "/api/join") {
    const which = calls.filter((c) => c.url === "/api/join").length;
    const view = which === 1
      ? { authority: "a.example", join_rev: 1, tenant: "acme", role: "gateway" }
      : { authority: "b.example", join_rev: 2, tenant: "acme", role: "gateway" };
    return { ok: true, status: 200, text: async () => JSON.stringify(view) };
  }
  return { ok: true, status: 200, text: async () => JSON.stringify({ role: "gateway", routes: [] }) };
};
const document = { getElementById: el, querySelector() { return null; } };
const context = {
  document, fetch, Promise, JSON, Error,
  sessionStorage: { getItem() { return null; }, setItem() {} },
  location: { hash: "", pathname: "/", search: "" },
  history: { replaceState() {} },
  window: {},
  console,
  setTimeout,
};
context.window.history = context.history;
context.window.location = context.location;
context.window.setTimeout = setTimeout;
vm.createContext(context);
vm.runInContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), context);
await new Promise((r) => setTimeout(r, 20));

el("code").value = "code-a";
el("confirm-authority").checked = true;
el("save-code").listeners.click();
if (el("confirm-authority").checked) throw new Error("save left the confirmation checked");
await new Promise((r) => setTimeout(r, 20));
if (el("confirm-authority").checked) throw new Error("save A restored the checkbox");

el("confirm-authority").checked = true;
el("yes-ai").listeners.click();
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 20));
const plan = calls.filter((c) => c.url === "/api/plan").pop();
if (!plan) throw new Error("plan was not sent");
if (plan.body.authority !== "a.example" || plan.body.join_rev !== 1 || plan.body.confirm_authority !== true) {
  throw new Error("plan confirmation " + JSON.stringify(plan.body));
}

el("code").value = "code-b";
el("save-code").listeners.click();
if (el("confirm-authority").checked) throw new Error("second save left A's confirmation checked");
const planCalls = calls.filter((c) => c.url === "/api/plan").length;
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 20));
if (calls.filter((c) => c.url === "/api/plan").length !== planCalls) {
  throw new Error("unchecked confirmation still posted a plan");
}
await new Promise((r) => setTimeout(r, 20));
el("confirm-authority").checked = true;
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 20));
const planB = calls.filter((c) => c.url === "/api/plan").pop();
if (!planB || planB.body.authority !== "b.example" || planB.body.join_rev !== 2) {
  throw new Error("plan B " + JSON.stringify(planB && planB.body));
}
console.log("ok");
`

const r4wAppJSMemberSmoke = `import { readFileSync } from "node:fs";
import vm from "node:vm";

const elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id, value: "", checked: false, textContent: "", disabled: false, hidden: false,
      listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      classList: { add() {}, remove() {} },
    };
  }
  return elements[id];
}
const calls = [];
let joinN = 0;
const fetch = async (url, opt) => {
  calls.push({ url, body: opt && opt.body ? JSON.parse(opt.body) : null });
  if (url === "/api/bootstrap") {
    return { ok: true, status: 200, text: async () => JSON.stringify({ capability: "cap", csrf: "csrf" }) };
  }
  if (url === "/api/join") {
    joinN++;
    const role = joinN === 1 ? "member" : (joinN === 2 ? "admin" : "gateway");
    return { ok: true, status: 200, text: async () => JSON.stringify({
      authority: "enroll.example", join_rev: joinN, tenant: "acme", role
    }) };
  }
  if (url === "/api/detect") {
    return { ok: true, status: 200, text: async () => JSON.stringify({ candidates: [] }) };
  }
  if (url === "/api/plan") {
    const role = (opt && opt.body && JSON.parse(opt.body).authority) ? "member" : "member";
    return { ok: true, status: 200, text: async () => JSON.stringify({ role, mode: "auto", accept_routes: true }) };
  }
  return { ok: true, status: 200, text: async () => "{}" };
};
const document = { getElementById: el, querySelector() { return null; } };
const context = {
  document, fetch, Promise, JSON, Error,
  sessionStorage: { getItem() { return null; }, setItem() {} },
  location: { hash: "", pathname: "/", search: "" },
  history: { replaceState() {} },
  window: {},
  console,
  setTimeout,
};
context.window.history = context.history;
context.window.location = context.location;
context.window.setTimeout = setTimeout;
vm.createContext(context);
vm.runInContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), context);
await new Promise((r) => setTimeout(r, 20));

function hiddenGateway() {
  return ["ai-question", "yes-ai", "no-ai", "detect", "device-label", "device", "probe", "whole-label"]
    .every((id) => el(id).hidden === true);
}

el("code").value = "member-code";
el("save-code").listeners.click();
await new Promise((r) => setTimeout(r, 20));
if (!hiddenGateway()) throw new Error("member save left gateway questions visible");
if (!el("role-state").textContent.includes("成员")) throw new Error("member text " + el("role-state").textContent);
el("confirm-authority").checked = true;
el("device").value = "10.1.1.1";
el("whole").checked = true;
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 30));
const memberPlan = calls.filter((c) => c.url === "/api/plan").pop();
if (!memberPlan) throw new Error("member recommend did not post a plan");
if (memberPlan.body.this_machine_is_local_ai !== false || memberPlan.body.whole_subnet !== false || memberPlan.body.device_ips.length !== 0) {
  throw new Error("member plan kept gateway answers " + JSON.stringify(memberPlan.body));
}
if (calls.some((c) => c.url === "/api/detect")) throw new Error("member recommend detected the network");

el("code").value = "admin-code";
el("save-code").listeners.click();
await new Promise((r) => setTimeout(r, 20));
if (!hiddenGateway()) throw new Error("admin save showed gateway questions");
if (!el("role-state").textContent.includes("管理员")) throw new Error("admin text " + el("role-state").textContent);
el("confirm-authority").checked = true;
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 30));
if (calls.filter((c) => c.url === "/api/plan").length !== 2) throw new Error("admin recommend did not post a plan");
if (calls.some((c) => c.url === "/api/detect")) throw new Error("admin recommend detected the network");

el("code").value = "gateway-code";
el("save-code").listeners.click();
await new Promise((r) => setTimeout(r, 20));
if (hiddenGateway()) throw new Error("gateway save kept the questions hidden");
const plans = calls.filter((c) => c.url === "/api/plan").length;
el("confirm-authority").checked = true;
el("recommend").listeners.click();
await new Promise((r) => setTimeout(r, 20));
if (calls.filter((c) => c.url === "/api/plan").length !== plans) {
  throw new Error("gateway recommend skipped the Local AI question");
}
if (!el("error").textContent.includes("Local AI")) throw new Error("missing question " + el("error").textContent);
console.log("ok");
`
