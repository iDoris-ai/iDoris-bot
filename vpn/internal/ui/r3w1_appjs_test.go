package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestR3W1AppJSBootstrapSmoke(t *testing.T) {
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
	if err := os.WriteFile(script, []byte(r3w1AppJSSmoke), 0o600); err != nil {
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

const r3w1AppJSSmoke = `import { readFileSync } from "node:fs";
import vm from "node:vm";

const store = {};
const sessionStorage = {
  getItem(k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
  setItem(k, v) { store[k] = String(v); },
};
let replaced = null;
let seen = null;
const location = { hash: "#k=abc123def456", pathname: "/", search: "" };
const history = {
  replaceState(_s, _t, url) { replaced = url; location.hash = ""; },
};
const fetch = async (url, opt) => {
  seen = { url, opt };
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ capability: "cap-1", csrf: "csrf-1" }),
  };
};
const document = {
  querySelector() { return null; },
  getElementById() {
    return {
      value: "",
      checked: false,
      textContent: "",
      addEventListener() {},
      classList: { add() {}, remove() {} },
    };
  },
};
const context = {
  sessionStorage, location, history, fetch, document,
  Promise, JSON, Error,
  window: {},
  console,
  setTimeout,
};
context.window.history = history;
context.window.location = location;
context.window.setTimeout = setTimeout;
vm.createContext(context);
vm.runInContext(readFileSync(new URL("./app.js", import.meta.url), "utf8"), context);
await new Promise((r) => setTimeout(r, 30));

if (!seen) throw new Error("fetch was not called");
if (seen.url !== "/api/bootstrap") throw new Error("url " + seen.url);
if (seen.opt.credentials !== "omit") throw new Error("credentials " + seen.opt.credentials);
if (seen.opt.headers["X-Idoris-UI"]) throw new Error("bootstrap request sent a session header");
const body = JSON.parse(seen.opt.body);
if (body.k !== "abc123def456") throw new Error("body " + seen.opt.body);
if (String(seen.url).includes("?")) throw new Error("bootstrap URL has a query");
if (replaced !== "/") throw new Error("replaceState " + replaced);
if (String(replaced).includes("abc123def456")) throw new Error("fragment left in history");
if (store.idoris_ui !== "cap-1" || store.idoris_csrf !== "csrf-1") {
  throw new Error("sessionStorage " + JSON.stringify(store));
}
if (Object.keys(store).some((k) => k.toLowerCase().includes("cookie"))) {
  throw new Error("cookie key " + JSON.stringify(store));
}
console.log("ok");
`
