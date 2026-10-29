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
    return body;
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
      document.getElementById("authority").textContent = "登记服务器：" + (view.authority || "");
      document.getElementById("code-state").textContent = "已保存。租户 " + view.tenant + "，角色 " + view.role + "。加入码已从输入框清掉。请核对上面的登记服务器。";
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
      document.getElementById("status").textContent = text;
      if (phase === "connected" || phase === "routes-pending-approval") {
        return;
      }
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
      var lines = ["配置已写入 " + (res.config_path || "")];
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
