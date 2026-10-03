/* dashboard.js — polls the CyberPulse GUI API and renders the live dashboard */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  let logOffset = 0;

  // ── Helpers ──────────────────────────────────────────────────────────────
  const api = async (url, opts) => {
    const res = await fetch(url, opts);
    let body = null;
    try { body = await res.json(); } catch (_) { /* non-JSON (404 page) */ }
    return { ok: res.ok, status: res.status, body };
  };

  const setMsg = (text, cls) => {
    const el = $("control-msg");
    el.textContent = text || "";
    el.className = "control-msg " + (cls || "");
  };

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const setPill = (state) => {
    const pill = $("status-pill");
    const map = {
      running: ["running", "Running…"],
      done: ["done", "Complete"],
      failed: ["failed", "Failed"],
      idle: ["idle", "Idle"],
    };
    const [cls, label] = map[state] || map.idle;
    pill.className = "pill " + cls;
    pill.textContent = label;
  };

  // ── Controls ─────────────────────────────────────────────────────────────
  async function startRun() {
    const payload = {
      mode: $("mode").value,
      target: $("target").value.trim(),
      patched_target: $("patched-target").value.trim(),
      timeout: parseInt($("timeout").value, 10) || 10,
      port_scan: $("port-scan").checked,
    };
    setMsg("Launching pipeline…");
    const { ok, body } = await api("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setMsg(body && body.message ? body.message : "Unknown response", ok ? "ok" : "err");
    if (ok) { logOffset = 0; $("console").textContent = ""; }
    refresh();
  }

  async function stopRun() {
    const { ok, body } = await api("/api/stop", { method: "POST" });
    setMsg(body && body.message ? body.message : "Stop requested", ok ? "ok" : "err");
    refresh();
  }

  // ── Rendering ────────────────────────────────────────────────────────────
  function renderPhases(phases) {
    (phases || []).forEach((p) => {
      const li = document.querySelector(`.stepper li[data-phase="${p.num}"]`);
      if (!li) return;
      li.className = ["active", "done", "skipped", "failed"].includes(p.state) ? p.state : "";
    });
  }

  function renderMetrics(status, validation, patchReport) {
    const summary = (validation && validation.summary) || {};
    $("m-confirmed").textContent = summary.confirmed ?? "–";
    $("m-partial").textContent = summary.partial ?? "–";
    $("m-failed").textContent = summary.failed ?? "–";
    $("m-patches").textContent = patchReport ? (patchReport.patches_applied ?? 0) : "–";

    const v = patchReport && patchReport.verification;
    const vEl = $("m-verify");
    if (v) {
      const passed = v.smoke_test === "passed" && v.syntax_ok && v.hygiene_ok;
      vEl.textContent = passed ? "✔ Verified" : "✖ " + String(v.smoke_test || "unknown").toUpperCase();
      vEl.className = "metric-value " + (passed ? "green" : "red");
    } else {
      vEl.textContent = "–";
      vEl.className = "metric-value dim";
    }

    $("m-duration").textContent = status.duration_s != null ? status.duration_s + "s" : "–";
  }

  function renderFindings(validation) {
    const tbody = document.querySelector("#findings tbody");
    const findings = ((validation && validation.findings) || [])
      .filter((f) => f.status === "CONFIRMED");
    if (!findings.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No confirmed vulnerabilities.</td></tr>';
      return;
    }
    tbody.innerHTML = findings.map((f) => `
      <tr>
        <td>${escapeHtml(f.type)}</td>
        <td>${escapeHtml(f.endpoint)}</td>
        <td><span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
        <td>${escapeHtml(f.cvss_score)}</td>
      </tr>`).join("");
  }

  function renderPatches(patchReport) {
    const host = $("patches");
    if (!patchReport || !patchReport.patches || !patchReport.patches.length) {
      host.innerHTML = '<p class="muted">No patches yet.</p>';
      return;
    }
    const items = patchReport.patches.map((p) => `
      <div class="patch-item">
        <h4>✔ ${escapeHtml(String(p.type).replace(/_/g, " "))}</h4>
        <p>${escapeHtml(p.description)}</p>
        <p>Endpoint: <code>${escapeHtml(p.endpoint)}</code> · <span class="cwe">${escapeHtml(p.cwe)}</span></p>
      </div>`).join("");

    const v = patchReport.verification;
    const checks = v ? `
      <div class="check-row">
        <span class="check ${v.syntax_ok ? "pass" : "fail"}">${v.syntax_ok ? "✔" : "✖"} syntax</span>
        <span class="check ${v.hygiene_ok ? "pass" : "fail"}">${v.hygiene_ok ? "✔" : "✖"} no stale symbols</span>
        <span class="check ${v.smoke_test === "passed" ? "pass" : "fail"}">${v.smoke_test === "passed" ? "✔" : "✖"} smoke test (${escapeHtml(v.smoke_test)})</span>
      </div>
      <p class="muted">${escapeHtml(v.smoke_detail || "")}</p>` : "";

    host.innerHTML = items + checks;
  }

  function renderRecon(recon) {
    const host = $("recon");
    if (!recon || recon.error) {
      host.innerHTML = '<p class="muted">No recon data yet.</p>';
      return;
    }
    const ports = (recon.open_ports || []).map((p) => `<span class="chip">${p}</span>`).join("") || "<em>none</em>";
    const vectors = (recon.attack_vectors || [])
      .map((v) => `<li>${escapeHtml(v.type)} → ${escapeHtml(v.endpoint)} <span class="muted">(${escapeHtml(v.severity)})</span></li>`)
      .join("") || "<li>none</li>";
    const endpoints = (recon.endpoints || []).slice(0, 14)
      .map((e) => `<span class="chip">${escapeHtml(e.path)}</span>`).join("") || "<em>none</em>";
    const stack = recon.tech_stack || {};
    const stackChips = Object.entries(stack)
      .map(([k, v]) => `<span class="chip">${escapeHtml(k)}: ${escapeHtml(v)}</span>`).join("") || "<em>unknown</em>";

    host.innerHTML = `
      <div class="recon-cell"><h4>Open Ports</h4><div>${ports}</div></div>
      <div class="recon-cell"><h4>Tech Stack</h4><div>${stackChips}</div></div>
      <div class="recon-cell"><h4>Attack Vectors (${(recon.attack_vectors || []).length})</h4><ul>${vectors}</ul></div>
      <div class="recon-cell"><h4>Endpoints (${(recon.endpoints || []).length})</h4><div>${endpoints}</div></div>`;
  }

  function renderRevalidation(revalidation) {
    const host = $("revalidation");
    if (!revalidation || !revalidation.summary) {
      host.innerHTML = '<p class="muted">Not run yet. Use mode <code>re-exploit</code> (or <code>full</code> with a patched target).</p>';
      return;
    }
    const s = revalidation.summary;
    const target = (revalidation._meta && revalidation._meta.target) || "patched target";
    const allClear = (s.confirmed || 0) === 0;
    const verdict = allClear
      ? '<span class="sev LOW">✔ REMEDIATED</span>'
      : `<span class="sev CRITICAL">✖ ${escapeHtml(s.confirmed)} STILL VULNERABLE</span>`;

    const rows = (revalidation.findings || []).map((f) => `
      <li>${escapeHtml(f.type)} → ${escapeHtml(f.endpoint)} <span class="muted">(${escapeHtml(f.status)})</span></li>`
    ).join("") || "<li>no findings</li>";

    host.innerHTML = `
      <div class="recon-cell">
        <h4>Verdict</h4>
        <p>${verdict}</p>
        <p class="muted">Re-tested <b>${escapeHtml(target)}</b></p>
      </div>
      <div class="recon-cell">
        <h4>Re-Test Summary</h4>
        <p class="muted">attempted ${s.total ?? 0} · confirmed ${s.confirmed ?? 0} · partial ${s.partial ?? 0} · failed ${s.failed ?? 0}</p>
      </div>
      <div class="recon-cell" style="grid-column: span 2">
        <h4>Per-Finding Status</h4>
        <ul>${rows}</ul>
      </div>`;
  }

  // ── SAST / DAST scanner panel ────────────────────────────────────────────
  function scannerCell(title, report, patched, totalKey, countKey) {
    if (!report) {
      return `<div class="recon-cell"><h4>${title}</h4><p class="muted">not run</p></div>`;
    }
    if (report.status === "skipped") {
      const hints = (report.install_hints || []).map((h) => `<code>${escapeHtml(h)}</code>`).join("<br>");
      return `<div class="recon-cell"><h4>${title}</h4>
        <p><span class="sev MEDIUM">SKIPPED</span></p>
        <p class="muted">${escapeHtml(report.reason || "")}</p>${hints}</div>`;
    }
    if (report.status !== "complete") {
      return `<div class="recon-cell"><h4>${title}</h4>
        <p><span class="sev CRITICAL">ERROR</span></p>
        <p class="muted">${escapeHtml(report.reason || "unknown error")}</p></div>`;
    }

    const before = (report.summary || {})[countKey] ?? 0;
    const after = patched && patched.status === "complete"
      ? ((patched.summary || {})[countKey] ?? 0) : null;
    const arrow = after === null ? ""
      : (after < before ? `<span class="muted"> → </span><b class="ok">${after}</b> ✔`
                        : `<span class="muted"> → </span><b class="bad">${after}</b>`);
    const sev = (report.summary || {})[totalKey] || {};

    return `<div class="recon-cell">
      <h4>${title}</h4>
      <p class="scanner-count">${before}${arrow}</p>
      <p class="muted">${escapeHtml(report.tool || "")}</p>
      <p class="muted">HIGH ${sev.HIGH || 0} · MED ${sev.MEDIUM || 0} · LOW ${sev.LOW || 0}</p>
    </div>`;
  }

  function renderScanners(sast, sastPatched, dast, dastPatched) {
    const host = $("scanners");
    if (!sast && !dast) {
      host.innerHTML = '<p class="muted">Not run yet. Add <code>--with-sast</code> / <code>--with-dast</code>,'
        + ' or run <code>--mode sast-only</code> / <code>--mode dast-only</code>.</p>';
      return;
    }
    host.innerHTML =
      scannerCell("🔎 SAST (Semgrep)", sast, sastPatched, "by_severity", "total") +
      scannerCell("🌐 DAST (OWASP ZAP)", dast, dastPatched, "by_risk", "total_alerts");
  }

  async function streamLog() {
    const { ok, body } = await api(`/api/log?offset=${logOffset}`);
    if (!ok || !body || !body.lines || !body.lines.length) return;
    logOffset = body.next_offset;
    const consoleEl = $("console");
    consoleEl.textContent += body.lines.join("\n") + "\n";
    consoleEl.scrollTop = consoleEl.scrollHeight;
    $("log-count").textContent = `${body.total} lines`;
  }

  // ── Poll loop ────────────────────────────────────────────────────────────
  async function refresh() {
    const status = await api("/api/status");
    if (!status.ok || !status.body) return;
    const s = status.body;

    setPill(s.running ? "running" : (s.exit_code == null ? "idle" : (s.exit_code === 0 ? "done" : "failed")));
    $("run-btn").disabled = !!s.running;
    $("stop-btn").disabled = !s.running;
    renderPhases(s.phases);

    const [validation, patchReport, recon, revalidation, sast, sastPatched, dast, dastPatched] =
      await Promise.all([
        api("/api/state/validation_report.json"),
        api("/api/state/patch_report.json"),
        api("/api/state/recon_results.json"),
        api("/api/state/revalidation_report.json"),
        api("/api/state/sast_report.json"),
        api("/api/state/sast_report_patched.json"),
        api("/api/state/dast_report.json"),
        api("/api/state/dast_report_patched.json"),
      ]);

    renderMetrics(s, validation.body, patchReport.body);
    renderFindings(validation.body);
    renderPatches(patchReport.body);
    renderRecon(recon.body);
    renderRevalidation(revalidation.body);
    renderScanners(sast.body, sastPatched.body, dast.body, dastPatched.body);
    await streamLog();
  }

  // ── Wire up ──────────────────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    $("run-btn").addEventListener("click", startRun);
    $("stop-btn").addEventListener("click", stopRun);
    refresh();
    setInterval(refresh, 1500);
  });

})();
