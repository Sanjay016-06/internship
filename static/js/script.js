const form = document.getElementById("scanForm");
const input = document.getElementById("targetInput");
const btn = document.getElementById("scanBtn");
const btnLabel = document.getElementById("btnLabel");
const termBody = document.getElementById("termBody");
const resultsSection = document.getElementById("results");
const resultsInner = document.getElementById("resultsInner");

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

const LOG_STEPS = [
  { text: "$ securescan --target {TARGET}", cls: "" },
  { text: "→ resolving host and opening connection...", cls: "muted" },
  { text: "→ inspecting TLS certificate chain...", cls: "muted" },
  { text: "→ reading HTTP response headers...", cls: "muted" },
  { text: "→ sweeping common ports...", cls: "muted" },
  { text: "→ checking cookie flags...", cls: "muted" },
  { text: "→ probing for exposed sensitive paths...", cls: "muted" },
  { text: "→ testing reflected input handling...", cls: "muted" },
  { text: "→ testing for SQL error signatures...", cls: "muted" },
  { text: "→ compiling report...", cls: "warn" },
];

let typingTimer = null;

function resetTerminal(target) {
  clearTimeout(typingTimer);
  termBody.innerHTML = "";
  let i = 0;
  function next() {
    if (i >= LOG_STEPS.length) return;
    const step = LOG_STEPS[i];
    const p = document.createElement("p");
    p.className = "line " + step.cls;
    p.textContent = step.text.replace("{TARGET}", target);
    termBody.appendChild(p);
    termBody.scrollTop = termBody.scrollHeight;
    i++;
    typingTimer = setTimeout(next, 260 + Math.random() * 220);
  }
  next();
}

function finishTerminal(ok) {
  clearTimeout(typingTimer);
  const p = document.createElement("p");
  p.className = "line " + (ok ? "ok" : "crit");
  p.textContent = ok ? "✓ scan complete — report generated" : "✗ scan failed";
  termBody.appendChild(p);
  termBody.scrollTop = termBody.scrollHeight;
}

function sevDot(sev) {
  return `<span class="sw" style="background:var(--${sev === "critical" ? "crit" : sev === "high" ? "high" : sev === "medium" ? "med" : sev === "low" ? "low" : "info"})"></span>`;
}

function renderResults(data, targetRaw) {
  resultsSection.classList.add("show");

  if (!data.ok) {
    resultsInner.innerHTML = `
      <div class="error-box">Could not complete the scan: ${escapeHtml(data.error || "Unknown error")}</div>
    `;
    return;
  }

  const counts = data.counts;
  const chips = SEV_ORDER.map(sev => `
    <div class="chip">${sevDot(sev)} ${SEV_LABEL[sev]} · ${counts[sev]}</div>
  `).join("");

  let head = `
    <div class="result-head">
      <div class="grade-badge">${data.grade}</div>
      <div class="result-meta">
        <h2>${escapeHtml(data.meta.final_url || data.meta.target)}</h2>
        <p>Score ${data.score}/100 · HTTP ${data.meta.status_code} · scanned in ${data.duration_ms}ms · ${data.scanned_at}</p>
      </div>
      <div class="severity-bar">${chips}</div>
    </div>
  `;

  let findingsHtml = "";
  if (data.findings.length === 0) {
    findingsHtml = `<div class="empty-state">No issues detected across the checks run. Nice work — keep monitoring regularly.</div>`;
  } else {
    for (const sev of SEV_ORDER) {
      const group = data.findings.filter(f => f.severity === sev);
      if (group.length === 0) continue;
      findingsHtml += `<div class="findings-group"><h4>${SEV_LABEL[sev]} (${group.length})</h4>`;
      for (const f of group) {
        findingsHtml += `
          <div class="finding ${f.severity}">
            <div class="top">
              <h5>${escapeHtml(f.title)}</h5>
              <span class="sev-tag ${f.severity}">${SEV_LABEL[f.severity]}</span>
            </div>
            <p>${escapeHtml(f.detail)}</p>
            <p class="rec"><b>Fix:</b> ${escapeHtml(f.recommendation)}</p>
          </div>
        `;
      }
      findingsHtml += `</div>`;
    }
  }

  resultsInner.innerHTML = head + findingsHtml;
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = input.value.trim();
  if (!target) return;

  btn.disabled = true;
  btnLabel.textContent = "Scanning...";
  resultsSection.classList.remove("show");
  resetTerminal(target);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    finishTerminal(!!data.ok);
    renderResults(data, target);
  } catch (err) {
    finishTerminal(false);
    renderResults({ ok: false, error: "Network error contacting the scan API." }, target);
  } finally {
    btn.disabled = false;
    btnLabel.textContent = "Run scan";
  }
});
