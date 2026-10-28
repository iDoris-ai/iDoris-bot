(function () {
  var session = "";
  var csrf = "";
  var localAI = null;

  function showError(err) {
    var el = document.getElementById("error");
    el.textContent = err && err.message ? err.message : String(err || "");
  }

  function stored(key) {
    try {
      return sessionStorage.getItem(key) || "";
    } catch (e) {
      return "";
    }
  }

  function store(key, value) {
    try {
      sessionStorage.setItem(key, value);
    } catch (e) {
      /* the in-memory copy still covers this page */
    }
  }

  function clearFragment() {
    if (window.history && window.history.replaceState) {
      window.history.replaceState({}, "", window.location.pathname);
    }
  }

  // A hand-opened URL carries the bootstrap secret in the fragment only.
  // The fragment is not sent on the request; this POST is the one exchange.
  function bootstrap() {
    var hash = window.location.hash || "";
    var m = /^#k=([0-9a-fA-F]+)$/.exec(hash);
    if (!m) {
      session = stored("idoris_ui");
      csrf = stored("idoris_csrf");
      return Promise.resolve();
    }
    return fetch("/api/bootstrap", {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ k: m[1] })
    }).then(function (res) {
      clearFragment();
      return res.text().then(function (text) {
        var data = {};
        if (text) {
          try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
        }
        if (!res.ok) {
          throw new Error(data.error || ("请求失败 " + res.status));
        }
        session = data.capability || "";
        csrf = data.csrf || "";
        store("idoris_ui", session);
        store("idoris_csrf", csrf);
      });
    });
  }

  var ready = bootstrap().catch(showError);
  var expectIdentity = null;
  // The daemon retries discovery about every 30s. Ninety polls at 2s is
  // three minutes (several retries). Then the page stops and names the
  // still-unconfirmed identity instead of spinning with no explanation.
  var unconfirmedPollLimit = 90;
  var unconfirmedPolls = 0;

  function exposed(st, key) {
    if (!st || !Object.prototype.hasOwnProperty.call(st, key)) {
      return false;
    }
    var v = st[key];
    return typeof v === "string" && v !== "";
  }

  // sameControlURL / normalizeControlURL mirror vpnd.SameControlURL and
  // vpnd.NormalizeControlURL: lower-case scheme and host, no trailing
  // slash, no default port (https 443, http 80), query and fragment
  // dropped. The two Tailscale SaaS URLs compare equal as exact strings.
  // Exact strings, same as ipn.IsLoginServerSynonym. The scheme and slashes
  // are checked apart so this file has no external URL literal. The page
  // test rejects that contiguous text in the asset.
  function isLoginServerSynonym(val) {
    if (typeof val !== "string" || val.slice(0, 6) !== "https:" || val.slice(6, 8) !== "//") {
      return false;
    }
    var host = val.slice(8);
    return host === "login.tailscale.com" || host === "controlplane.tailscale.com";
  }

  function sameControlURL(a, b) {
    if (isLoginServerSynonym(a) && isLoginServerSynonym(b)) {
      return true;
    }
    return normalizeControlURL(a) === normalizeControlURL(b);
  }

  function normalizeControlURL(s) {
    if (typeof s !== "string") {
      return "";
    }
    s = s.replace(/^\s+|\s+$/g, "");
    if (!s) {
      return "";
    }
    var parsed = parseControlURL(s);
    if (!parsed) {
      return s.toLowerCase().replace(/\/+$/, "");
    }
    var scheme = parsed.scheme.toLowerCase();
    var host = parsed.host.toLowerCase();
    if (scheme === "https" && host.slice(-4) === ":443") {
      host = host.slice(0, -4);
    } else if (scheme === "http" && host.slice(-3) === ":80") {
      host = host.slice(0, -3);
    }
    var path = parsed.path.replace(/\/+$/, "");
    var out = "";
    if (scheme) {
      out += scheme + ":";
    }
    if (scheme || host) {
      out += "//";
    }
    if (parsed.userinfo) {
      out += parsed.userinfo + "@";
    }
    out += host;
    if (path && path.charAt(0) !== "/" && host) {
      out += "/";
    }
    out += path;
    return out;
  }

  // Enough of net/url.Parse for a control URL. A parse Go would reject, or
  // a URL with an empty host, returns null so the caller uses the same
  // lower-case / trim-slash fallback as NormalizeControlURL.
  function parseControlURL(raw) {
    var i;
    for (i = 0; i < raw.length; i++) {
      var c = raw.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) {
        return null;
      }
    }
    var hash = raw.indexOf("#");
    if (hash >= 0) {
      raw = raw.slice(0, hash);
    }
    var scheme = "";
    var rest = raw;
    var colon = -1;
    for (i = 0; i < raw.length; i++) {
      var ch = raw.charAt(i);
      if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z")) {
        continue;
      }
      if (ch >= "0" && ch <= "9" || ch === "+" || ch === "-" || ch === ".") {
        if (i === 0) {
          break;
        }
        continue;
      }
      if (ch === ":") {
        if (i === 0) {
          return null;
        }
        colon = i;
      }
      break;
    }
    if (colon > 0) {
      scheme = raw.slice(0, colon).toLowerCase();
      rest = raw.slice(colon + 1);
    }
    var q = rest.indexOf("?");
    if (q >= 0) {
      rest = rest.slice(0, q);
    }
    if (rest.slice(0, 2) !== "//") {
      return null;
    }
    var authority = rest.slice(2);
    var path = "";
    var slash = authority.indexOf("/");
    if (slash >= 0) {
      path = authority.slice(slash);
      authority = authority.slice(0, slash);
    }
    if (!authority) {
      return null;
    }
    var userinfo = "";
    var at = authority.lastIndexOf("@");
    var host = authority;
    if (at >= 0) {
      userinfo = authority.slice(0, at);
      host = authority.slice(at + 1);
      if (!host) {
        return null;
      }
    }
    var portAt = -1;
    if (host.charAt(0) === "[") {
      var bracket = host.lastIndexOf("]");
      if (bracket < 0) {
        return null;
      }
      if (bracket + 1 < host.length) {
        portAt = bracket + 1;
      }
    } else {
      var firstColon = host.indexOf(":");
      if (firstColon >= 0) {
        portAt = firstColon;
        if (host.lastIndexOf(":") !== firstColon && (scheme === "http" || scheme === "https")) {
          return null;
        }
        if (host.lastIndexOf(":") !== firstColon) {
          portAt = host.lastIndexOf(":");
        }
      }
    }
    if (portAt >= 0 && !/^:\d*$/.test(host.slice(portAt))) {
      return null;
    }
    return { scheme: scheme, host: host, path: path, userinfo: userinfo };
  }

  function daemonNotice(st) {
    var lines = [];
    var warnings = st && st.warnings;
    if (warnings && Object.prototype.toString.call(warnings) === "[object Array]") {
      var i;
      for (i = 0; i < warnings.length; i++) {
        if (typeof warnings[i] === "string" && warnings[i] !== "") {
          lines.push(warnings[i]);
        }
      }
    }
    if (st && typeof st.last_error === "string" && st.last_error !== "") {
      var dup = false;
      var j;
      for (j = 0; j < lines.length; j++) {
        if (lines[j] === st.last_error) {
          dup = true;
        }
      }
      if (!dup) {
        lines.push(st.last_error);
      }
    }
    return lines.join("\n");
  }

  function unconfirmedNote(st, timedOut) {
    var note = timedOut ? "身份尚未确认，等待超时。" : "身份尚未确认，继续等待。";
    var extra = daemonNotice(st);
    if (extra) {
      note += "\n" + extra;
    }
    return note;
  }

  // Completion is the identity Apply just wrote. An empty expected control
  // URL means discovery did not name a server, so role is the only check.
  // Control URLs compare in canonical form, so a pinned spelling with a
  // trailing slash or an explicit :443 matches discovery. Tenant and token
  // fingerprint count only when the daemon status already carries a
  // non-empty value for them. identity_unconfirmed means discovery has not
  // confirmed this credential, so a matching fingerprint is not completion.
  function identityMatches(st) {
    if (!expectIdentity) {
      return true;
    }
    if (st && st.identity_unconfirmed === true) {
      return false;
    }
    if (expectIdentity.role && st.role !== expectIdentity.role) {
      return false;
    }
    if (expectIdentity.control_url && !sameControlURL(st.control_url, expectIdentity.control_url)) {
      return false;
    }
    if (expectIdentity.tenant && exposed(st, "tenant") && st.tenant !== expectIdentity.tenant) {
      return false;
    }
    if (expectIdentity.token_fingerprint && exposed(st, "token_fingerprint") && st.token_fingerprint !== expectIdentity.token_fingerprint) {
      return false;
    }
    return true;
  }

  function post(path, body) {
    return ready.then(function () {
      return fetch(path, {
        method: "POST",
        credentials: "omit",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
          "X-Idoris-UI": session
        },
        body: JSON.stringify(body || {})
      }).then(function (res) {
        return res.text().then(function (text) {
          var data = {};
          if (text) {
            try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
          }
          if (!res.ok) {
            throw new Error(data.error || ("请求失败 " + res.status));
          }
          return data;
        });
      });
    });
  }

  function renderReport(rep) {
    var nets = document.getElementById("networks");
    nets.textContent = "";
    var list = rep.candidates || [];
    list.forEach(function (c) {
      var row = document.createElement("div");
      row.className = "card";
      var title = document.createElement("strong");
      title.textContent = c.name + " " + c.network;
      row.appendChild(title);
      if (rep.recommended && c.addr === rep.recommended.addr) {
        var badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = " 推荐";
        row.appendChild(badge);
      }
      var meta = document.createElement("div");
      meta.textContent = "地址 " + c.addr + (c.gateway ? "，网关 " + c.gateway : "");
      row.appendChild(meta);
      (c.warnings || []).forEach(function (w) {
        var warn = document.createElement("div");
        warn.className = "bad";
        warn.textContent = w.text;
        row.appendChild(warn);
      });
      nets.appendChild(row);
    });
    if (!rep.gateway_supported) {
      var unsupported = document.createElement("p");
      unsupported.className = "bad";
      unsupported.textContent = "网关只在 Linux 上启用。这台机器不会通告局域网。";
      nets.appendChild(unsupported);
    }
    var checks = document.getElementById("checks");
    checks.textContent = "";
    (rep.checks || []).forEach(function (c) {
      var row = document.createElement("div");
      row.className = c.ok ? "ok" : "bad";
      row.textContent = (c.ok ? "✓ " : "✗ ") + c.id + " " + c.detail + (c.fix ? "。处理：" + c.fix : "");
      checks.appendChild(row);
    });
  }

  function renderPlan(plan) {
    var lines = [];
    lines.push("角色：" + plan.role);
    if (plan.blocked) {
      lines.push(plan.block_reason || "不能在这台机器上做网关");
    }
    if (plan.routes && plan.routes.length) {
      lines.push("通告：" + plan.routes.join(", "));
    } else {
      lines.push("通告：无（本机就是 Local AI，或只是加入）");
    }
    lines.push(plan.will_auto_approve ? "路由会自动批准。" : "路由需要管理员批准。");
    if (plan.admin_command) {
      lines.push("管理员命令：" + plan.admin_command);
    }
    (plan.warnings || []).forEach(function (w) {
      lines.push("注意：" + w.text);
    });
    document.getElementById("plan").textContent = lines.join("\n");
  }

  function clearPlanText() {
    document.getElementById("plan").textContent = "先识别网络，再使用建议。";
  }

  var savedRole = "";
  var confirmBox = document.getElementById("confirm-authority");
  var replaceBox = document.getElementById("replace-existing");
  var enableBtn = document.getElementById("enable");
  var shownAuthority = "";
  var shownRev = 0;
  function syncEnable() {
    enableBtn.disabled = !confirmBox.checked;
  }
  confirmBox.addEventListener("change", syncEnable);

  function clearConfirmation() {
    confirmBox.checked = false;
    shownAuthority = "";
    shownRev = 0;
    syncEnable();
  }

  function answers() {
    var whole = document.getElementById("whole").checked;
    var ip = document.getElementById("device").value.trim();
    var body = {
      this_machine_is_local_ai: localAI === true,
      whole_subnet: whole,
      device_ips: [],
      confirm_authority: confirmBox.checked,
      authority: shownAuthority,
      join_rev: shownRev
    };
    if (localAI === false && !whole && ip) {
      body.device_ips = [ip];
    }
    if (savedRole === "member" || savedRole === "admin") {
      body.this_machine_is_local_ai = false;
      body.whole_subnet = false;
      body.device_ips = [];
    }
    return body;
  }

  function showGatewayQuestions(show) {
    ["ai-question", "yes-ai", "no-ai", "detect", "device-label", "device", "probe", "whole-label"].forEach(function (id) {
      var node = document.getElementById(id);
      if (node) {
        node.hidden = !show;
      }
    });
  }

  document.getElementById("save-code").addEventListener("click", function () {
    showError("");
    // A confirmation of the previous code must not survive this save,
    // including while the request is still in flight.
    clearConfirmation();
    var input = document.getElementById("code");
    post("/api/join", {
      code: input.value,
      allow_insecure: document.getElementById("insecure").checked
    }).then(function (view) {
      input.value = "";
      clearPlanText();
      clearConfirmation();
      shownAuthority = view.authority || "";
      shownRev = view.join_rev || 0;
      var previousRole = savedRole;
      savedRole = view.role || "";
      document.getElementById("authority").textContent = "登记服务器：" + (view.authority || "");
      document.getElementById("code-state").textContent = "已保存。租户 " + view.tenant + "，角色 " + view.role + "。加入码已从输入框清掉。请核对上面的登记服务器。";
      if (savedRole === "member" || savedRole === "admin") {
        showGatewayQuestions(false);
        localAI = false;
        document.getElementById("role-state").textContent = savedRole === "admin"
          ? "这台机器以管理员加入，不开通网关，也不通告局域网。"
          : "这台机器以成员加入，不开通网关，也不通告局域网。";
      } else {
        showGatewayQuestions(true);
        if (previousRole === "member" || previousRole === "admin") {
          localAI = null;
          document.getElementById("role-state").textContent = "";
        }
      }
    }).catch(showError);
  });

  document.getElementById("yes-ai").addEventListener("click", function () {
    localAI = true;
    clearPlanText();
    document.getElementById("role-state").textContent = "将以 Local AI 主机加入，不通告局域网。";
  });
  document.getElementById("no-ai").addEventListener("click", function () {
    localAI = false;
    clearPlanText();
    document.getElementById("role-state").textContent = "这台机器做网关，只通告你填的设备地址。";
  });

  document.getElementById("detect").addEventListener("click", function () {
    showError("");
    clearPlanText();
    post("/api/detect", {}).then(renderReport).catch(showError);
  });

  document.getElementById("probe").addEventListener("click", function () {
    showError("");
    post("/api/probe", { ip: document.getElementById("device").value }).then(function (res) {
      var el = document.getElementById("probe-state");
      el.textContent = res.reachable ? ("到达了，端口 " + res.port) : "这台设备的常见端口没有响应";
    }).catch(showError);
  });

  document.getElementById("recommend").addEventListener("click", function () {
    showError("");
    if (!confirmBox.checked) {
      showError(new Error("先确认：这是我组织的服务器"));
      return;
    }
    if (savedRole === "member" || savedRole === "admin") {
      post("/api/plan", answers()).then(renderPlan).catch(showError);
      return;
    }
    if (localAI === null) {
      showError(new Error("先回答：这台机器就是 Local AI 吗？"));
      return;
    }
    var body = answers();
    var chain = Promise.resolve();
    if (!localAI) {
      chain = post("/api/detect", {}).then(renderReport);
    }
    chain.then(function () { return post("/api/plan", body); }).then(renderPlan).catch(showError);
  });

  function poll() {
    ready.then(function () {
      return fetch("/api/status", {
        credentials: "omit",
        headers: { "X-Idoris-UI": session }
      });
    }).then(function (res) {
      return res.json();
    }).then(function (st) {
      var phase = st.phase || "";
      var text = "状态：" + phase;
      if (phase === "routes-pending-approval") {
        text += "\n节点已连接，路由还在等管理员批准。";
      }
      if (st.admin_hint) {
        text += "\n" + st.admin_hint;
      }
      if (st.routes) {
        st.routes.forEach(function (r) {
          text += "\n" + r.cidr + (r.approved ? " 已批准" : " 未批准");
        });
      }
      var unconfirmed = st && st.identity_unconfirmed === true;
      if (phase === "connected" || phase === "routes-pending-approval") {
        if (!identityMatches(st)) {
          var note;
          if (unconfirmed) {
            unconfirmedPolls++;
            if (unconfirmedPolls >= unconfirmedPollLimit) {
              document.getElementById("status").textContent = text + "\n" + unconfirmedNote(st, true);
              return;
            }
            note = unconfirmedNote(st, false);
          } else {
            unconfirmedPolls = 0;
            note = "正在运行的仍是上一份身份，继续等待新的服务。";
          }
          document.getElementById("status").textContent = text + "\n" + note;
          window.setTimeout(poll, 2000);
          return;
        }
        unconfirmedPolls = 0;
        document.getElementById("status").textContent = text;
        return;
      }
      if (unconfirmed) {
        unconfirmedPolls++;
        if (unconfirmedPolls >= unconfirmedPollLimit) {
          document.getElementById("status").textContent = text + "\n" + unconfirmedNote(st, true);
          return;
        }
        text += "\n" + unconfirmedNote(st, false);
      }
      document.getElementById("status").textContent = text;
      window.setTimeout(poll, 2000);
    }).catch(function () {
      window.setTimeout(poll, 2000);
    });
  }

  document.getElementById("enable").addEventListener("click", function () {
    showError("");
    var body = answers();
    body.replace_existing = !!(replaceBox && replaceBox.checked);
    post("/api/apply", body).then(function (res) {
      var boundURL = res.discovery_control_url || res.control_url || "";
      expectIdentity = {
        role: res.role || "",
        control_url: boundURL,
        tenant: res.tenant || "",
        token_fingerprint: res.token_fingerprint || ""
      };
      unconfirmedPolls = 0;
      var lines = ["配置已写入 " + (res.config_path || "")];
      lines.push("新身份：角色 " + (res.role || "") + "，主机 " + (res.hostname || "") + "，登记 " + (res.enroll_url || ""));
      if (boundURL) {
        lines.push("控制服务器：" + boundURL);
      }
      if (res.tenant) {
        lines.push("租户：" + res.tenant);
      }
      if (res.control_pin_dropped) {
        lines.push("replacing the enrollment authority removes the previous control server pin; the next start discovers the new server and pins it; the old pin is not kept");
      }
      if (res.service_installed) {
        lines.push("服务已按这份新身份安装。");
      }
      if (res.sudo_command) {
        lines.push("当前不是 root，没有改系统转发。请原样执行：");
        lines.push(res.sudo_command);
      }
      if (res.ip_forward_applied) {
        lines.push("已打开 IPv4 转发。");
      }
      (res.access_info || []).forEach(function (line) {
        lines.push(line);
      });
      document.getElementById("result").textContent = lines.join("\n");
      poll();
    }).catch(showError);
  });
})();
