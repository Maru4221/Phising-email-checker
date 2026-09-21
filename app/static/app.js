const $ = (id) => document.getElementById(id);

let lastAnalysis = null;
let bulkRows = [];                
let bulkSort = { key: "score", dir: -1 };
const BULK_CHUNK = 40;            

const dropzone = $("dropzone");
const fileInput = $("fileInput");
const rawInput = $("rawInput");

dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    $("status").textContent = `Loaded: ${e.dataTransfer.files[0].name}` +
      (e.dataTransfer.files.length > 1 ? ` (+${e.dataTransfer.files.length - 1} more — use "Bulk analyze")` : "");
  }
});
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) $("status").textContent = `Loaded: ${fileInput.files[0].name}` +
    (fileInput.files.length > 1 ? ` (+${fileInput.files.length - 1} more — use "Bulk analyze")` : "");
});

async function currentEmail() {
  if (fileInput.files.length) return fileInput.files[0];
  const text = rawInput.value.trim();
  if (!text) throw new Error("No email provided — drop a .eml or paste raw source.");
  return text;
}

async function sendEmail(url, raw) {
  let resp;
  if (raw instanceof File) {
    const fd = new FormData();
    fd.append("file", raw, raw.name);
    resp = await fetch(url, { method: "POST", body: fd });
  } else {
    resp = await fetch(url, { method: "POST", body: raw, headers: { "Content-Type": "message/rfc822" } });
  }
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || resp.statusText);
  return data;
}

function esc(s) {
  const div = document.createElement("div");
  div.textContent = String(s ?? "");
  return div.innerHTML;
}

function setStatus(msg, isError = false) {
  const el = $("status");
  el.textContent = msg;
  el.style.color = isError ? "var(--red)" : "var(--muted)";
}

async function walkDrop(dataTransfer) {
  const files = [];
  const entries = [];
  for (const item of dataTransfer.items) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) entries.push(entry);
  }
  if (!entries.length) return [...dataTransfer.files];

  async function walk(entry, path) {
    if (entry.isFile) {
      const f = await new Promise((res, rej) => entry.file(res, rej));
      Object.defineProperty(f, "webkitRelativePath", { value: path + f.name });
      files.push(f);
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const child of batch) await walk(child, path + entry.name + "/");
      }
    }
  }
  for (const entry of entries) await walk(entry, "");
  return files;
}

function pickedFiles() {
  const all = [...fileInput.files];
  return all.filter((f) => /\.(eml|msg|txt)$/i.test(f.name));
}

async function runBulk(files) {
  if (!files.length) return setStatus("No .eml/.msg/.txt files found.", true);

  bulkRows = [];
  $("bulkSection").classList.remove("hidden");
  $("bulkBody").innerHTML = "";

  let done = 0;
  for (let i = 0; i < files.length; i += BULK_CHUNK) {
    const chunk = files.slice(i, i + BULK_CHUNK);
    setStatus(`Analyzing ${done + 1}–${done + chunk.length} of ${files.length}…`);
    const fd = new FormData();
    for (const f of chunk) fd.append("files", f, f.name);
    const resp = await fetch("/api/bulk", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || resp.statusText);
    bulkRows.push(...data.rows);
    done += chunk.length;
    drawTable();
  }
  $("bulkCount").textContent = `(${bulkRows.length} emails)`;
  setStatus(`Bulk analysis complete — ${bulkRows.length} emails.`);
}

function sortedRows() {
  const { key, dir } = bulkSort;
  const q = ($("bulkFilter").value || "").toLowerCase();
  const rows = bulkRows.filter((r) =>
    !q || [r.name, r.subject, r.from, r.verdict, r.origin_ip, ...(r.top_findings || [])]
      .some((v) => String(v || "").toLowerCase().includes(q)));
  rows.sort((a, b) => {
    let va = a[key] ?? "", vb = b[key] ?? "";
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
    va = String(va).toLowerCase(); vb = String(vb).toLowerCase();
    if (va === "" && vb !== "") return 1;
    if (vb === "" && va !== "") return -1;
    return va < vb ? -dir : va > vb ? dir : 0;
  });
  return rows;
}

function drawTable() {
  const rows = sortedRows();
  const body = $("bulkBody");
  body.innerHTML = rows.map((r) => {
    if (r.error && !r.id) {
      return `<tr class="row-error"><td>—</td><td>—</td>
        <td class="mono">${esc(r.name)}</td><td colspan="3" class="status">⚠ ${esc(r.error)}</td><td></td></tr>`;
    }
    const chip = r.error
      ? `<span class="chip err">error</span>`
      : `<span class="chip ${r.verdict.toLowerCase()}">${esc(r.verdict)}</span>`;
    return `<tr class="rowlink" data-id="${esc(r.id)}">
      <td>${chip}</td>
      <td class="mono">${r.error ? "—" : r.score}</td>
      <td class="mono">${esc(r.name)}</td>
      <td>${esc(r.subject)}</td>
      <td class="mono">${esc(r.from)}</td>
      <td class="mono">${r.origin_ip ? esc(r.origin_ip) + (r.helo_mismatch ? " ⚠" : "") : "—"}</td>
      <td class="mono small">${esc((r.top_findings || []).join(" · "))}${r.error ? ` ⚠ ${esc(r.error)}` : ""}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="status">No rows.</td></tr>`;

  for (const th of $("bulkTable").querySelectorAll("th[data-sort]")) {
    th.classList.toggle("sorted", th.dataset.sort === bulkSort.key);
    th.textContent = th.textContent.replace(/ [▲▼]$/, "");
    if (th.dataset.sort === bulkSort.key) th.textContent += bulkSort.dir > 0 ? " ▲" : " ▼";
  }
}

$("bulkTable").querySelectorAll("th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    bulkSort = { key, dir: bulkSort.key === key ? -bulkSort.dir : (key === "score" ? -1 : 1) };
    drawTable();
  });
});
$("bulkFilter").addEventListener("input", drawTable);

$("bulkBody").addEventListener("click", async (e) => {
  const tr = e.target.closest("tr.rowlink");
  if (!tr || !tr.dataset.id) return;
  try {
    setStatus("Loading email…");
    const resp = await fetch(`/api/analysis/${encodeURIComponent(tr.dataset.id)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || resp.statusText);
    lastAnalysis = data;
    drawAnalysis(data);
    $("enrichment").innerHTML = '<span class="status">Not yet enriched.</span>';
    $("results").scrollIntoView({ behavior: "smooth" });
    setStatus("Loaded from bulk results — you can enrich or report it like a single email.");
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("bulkCsvBtn").addEventListener("click", () => {
  const cols = ["File", "Verdict", "Score", "From", "Subject", "OriginIP", "HELO_mismatch", "URLs", "Attachments", "TopFindings", "Error"];
  const q = (v) => JSON.stringify(String(v ?? ""));
  const lines = [cols.join(",")];
  for (const r of bulkRows) {
    lines.push([r.name, r.verdict ?? "", r.score ?? "", r.from, r.subject, r.origin_ip ?? "",
      r.helo_mismatch ? "yes" : "no", r.urls ?? "", r.attachments ?? "",
      (r.top_findings || []).join("; "), r.error ?? ""].map(q).join(","));
  }
  const blob = new Blob([lines.join("\r\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "phish-triage-bulk.csv";
  a.click();
  URL.revokeObjectURL(a.href);
});

$("bulkClearBtn").addEventListener("click", () => {
  bulkRows = [];
  $("bulkBody").innerHTML = "";
  $("bulkSection").classList.add("hidden");
});

$("bulkBtn").addEventListener("click", async () => {
  try {
    $("bulkBtn").disabled = true;
    const files = pickedFiles();
    await runBulk(files);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("bulkBtn").disabled = false;
  }
});

dropzone.addEventListener("drop", async (e) => {
  const items = e.dataTransfer.items;
  const hasDir = items && [...items].some((it) => it.webkitGetAsEntry?.()?.isDirectory);
  if (!hasDir) return;
  try {
    $("bulkBtn").disabled = true;
    setStatus("Collecting folder contents…");
    const files = await walkDrop(e.dataTransfer);
    const emls = files.filter((f) => /\.(eml|msg|txt)$/i.test(f.name));
    if (!emls.length) return setStatus("No .eml/.msg/.txt files in that folder.", true);
    fileInput.files = e.dataTransfer.files;
    await runBulk(emls);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("bulkBtn").disabled = false;
  }
});

function drawTIStatus() {
  const el = $("tiStatus");
  if (!el) return;
  const s = lastAnalysis?.ti_feed_status;
  if (!s) { el.textContent = ""; return; }
  const bits = [];
  bits.push(s.urlhaus ? "URLhaus ✓" : "URLhaus (no key)");
  bits.push(s.virustotal ? "VirusTotal ✓" : "VirusTotal (no key)");
  bits.push(s.abuseipdb ? "AbuseIPDB ✓" : "AbuseIPDB (no key)");
  el.innerHTML = `<span class="mono">TI feeds: ${bits.join(" · ")}</span>`;
}

function drawAnalysis(a) {
  $("results").classList.remove("hidden");

  const badge = $("verdictBadge");
  badge.textContent = a.score.verdict;
  badge.className = a.score.verdict.toLowerCase();
  $("verdictScore").textContent = `risk score: ${a.score.score}`;

  const list = $("findingsList");
  list.innerHTML = "";
  if (!a.findings.length) {
    list.innerHTML = `<li class="sev-info"><span class="sev-tag">info</span>No notable findings — parsed cleanly.</li>`;
  }
  for (const f of a.findings) {
    const li = document.createElement("li");
    li.className = `sev-${f.severity}`;
    li.innerHTML = `<span class="sev-tag">${esc(f.severity)}</span>${esc(f.title)}
      <span class="detail">${esc(f.detail)} <em>[${esc(f.source)}]</em></span>`;
    list.appendChild(li);
  }

  const origin = a.origin || {};
  const rows = [
    ["From", `${a.headers.display_name || ""} <${a.headers.from || ""}>`],
    ["Reply-To", (a.headers.reply_to || []).join(", ") || "—"],
    ["Return-Path", a.headers.return_path || "—"],
    ["Origin IP", origin.ip
      ? esc(origin.ip) + (origin.helo_mismatch ? ` (HELO claimed ${esc(origin.helo_ip)} — spoofed)` : "")
      : "—"],
    ["Subject", a.headers.subject],
    ["Date", a.headers.date],
    ["Message-ID", a.headers.message_id],
  ];
  $("headerTable").innerHTML = rows.map(
    ([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`
  ).join("");

  const auth = a.headers.authentication || {};
  $("authBadges").innerHTML = ["spf", "dkim", "dmarc"].map((mech) => {
    const v = auth[mech];
    const cls = v ? v.toLowerCase() : "missing";
    const label = v ? `${mech.toUpperCase()} ${v}` : `${mech.toUpperCase()} missing`;
    return `<span class="badge ${cls}">${esc(label)}</span>`;
  }).join("");

  $("receivedList").innerHTML = (a.headers.received_chain || [])
    .map((hop) => `<li>from ${esc(hop.from)} → by ${esc(hop.by)}</li>`).join("")
    || "<li>(none)</li>";

  $("urlList").innerHTML = a.iocs.urls.map((u) => `<li>${esc(u)}</li>`).join("") || "<li>—</li>";
  $("domainList").innerHTML = a.iocs.domains.map((d) => `<li>${esc(d)}</li>`).join("") || "<li>—</li>";
  $("ipList").innerHTML = a.iocs.ips.map((ip) => `<li>${esc(ip)}</li>`).join("") || "<li>—</li>";
  $("attachList").innerHTML = (a.attachments || []).map((at) =>
    `<li class="${at.risky ? "risky" : ""}">${esc(at.filename)} — ${esc(at.content_type)}, ${at.size_bytes} bytes${at.risky ? " ⚠ risky" : ""}${at.sha256 ? ` — sha256: ${esc(at.sha256)}` : ""}</li>`
  ).join("") || "<li>—</li>";

  drawTIStatus();
}

function drawEnrichment(en) {
  const el = $("enrichment");
  const rows = [];
  const line = (color, icon, text) =>
    rows.push(`<div class="mono" style="color:${color}">${icon} ${text}</div>`);

  for (const r of en.urlhaus_hosts || []) {
    if (r.found) line("var(--red)", "⛔", `URLhaus: origin ${esc(r.queried)} hosts known malware URL(s) (${r.url_count ?? "?"} tracked)`);
    else if (r.skipped) line("var(--muted)", "—", `URLhaus host check skipped — ${esc(r.skipped)}`);
    else if (r.error) line("var(--amber)", "⚠", `URLhaus: ${esc(r.queried)} — ${esc(r.error)}`);
    else line("var(--green)", "✓", `URLhaus: origin ${esc(r.queried)} — clean`);
  }
  for (const r of en.abuseipdb || []) {
    const s = r.abuse_confidence_score ?? 0;
    const color = s >= 75 ? "var(--red)" : s >= 25 ? "var(--amber)" : "var(--green)";
    const icon = s >= 75 ? "⛔" : s >= 25 ? "⚠" : "✓";
    line(color, icon, `AbuseIPDB: ${esc(r.queried)} — confidence ${s}/100, ${r.total_reports ?? 0} report(s)`
      + (r.country_code ? `, ${esc(r.country_code)}` : "") + (r.usage_type ? `, ${esc(r.usage_type)}` : ""));
  }

  for (const r of en.urlhaus_urls || []) {
    if (r.found) line("var(--red)", "⛔", `URLhaus: ${esc(r.queried)} — ${esc(r.threat || "known malware URL")}`);
    else if (r.skipped) line("var(--muted)", "—", `URLhaus URL check skipped — ${esc(r.skipped)}`);
    else if (r.error) line("var(--amber)", "⚠", `URLhaus: ${esc(r.queried)} — ${esc(r.error)}`);
    else line("var(--green)", "✓", `URLhaus: ${esc(r.queried)} — clean`);
  }

  for (const r of en.urlhaus_hashes || []) {
    if (r.found) line("var(--red)", "⛔", `URLhaus payload: ${esc(r.queried)} — ${esc(r.signature || "known malware")}`);
    else if (r.skipped) line("var(--muted)", "—", `URLhaus payload check skipped — ${esc(r.skipped)}`);
    else if (r.error) line("var(--amber)", "⚠", `URLhaus: ${esc(r.queried)} — ${esc(r.error)}`);
    else line("var(--green)", "✓", `URLhaus payload: ${esc(r.queried)} — clean`);
  }

  for (const r of [...(en.vt_urls || []), ...(en.vt_hashes || [])]) {
    const bad = (r.malicious || 0) + (r.suspicious || 0);
    const color = bad ? "var(--red)" : "var(--green)";
    const extra = r.popular_threat_name ? ` (${esc(r.popular_threat_name)})` : "";
    line(color, bad ? "⛔" : "✓", `VirusTotal: ${esc(r.queried)} — ${r.malicious ?? 0} malicious, ${r.suspicious ?? 0} suspicious${extra}`);
  }

  el.innerHTML = rows.join("") || '<div class="status">No IOCs to enrich.</div>';
}

$("analyzeBtn").addEventListener("click", async () => {
  try {
    $("analyzeBtn").disabled = true;
    setStatus("Analyzing…");
    const raw = await currentEmail();
    lastAnalysis = await sendEmail("/api/analyze", raw);
    drawAnalysis(lastAnalysis);
    $("enrichment").innerHTML = '<span class="status">Not yet enriched.</span>';
    $("reportBox").value = "";
    setStatus("Done.");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("analyzeBtn").disabled = false;
  }
});

$("enrichBtn").addEventListener("click", async () => {
  if (!lastAnalysis) return setStatus("Analyze an email first.", true);
  try {
    $("enrichBtn").disabled = true;
    setStatus("Querying URLhaus / VirusTotal…");
    const resp = await fetch("/api/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastAnalysis),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || resp.statusText);
    lastAnalysis.findings = data.findings;
    lastAnalysis.score = data.score;
    drawAnalysis(lastAnalysis);
    drawEnrichment(data.enrichment);
    setStatus("Enrichment complete — verdict updated if new findings were added.");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("enrichBtn").disabled = false;
  }
});

$("reportBtn").addEventListener("click", async () => {
  try {
    $("reportBtn").disabled = true;
    setStatus("Building full report…");
    const raw = await currentEmail();
    const data = await sendEmail("/api/report", raw);
    drawAnalysis(data.analysis);
    $("reportBox").value = data.markdown;
    lastAnalysis = data.analysis;
    if (data.analysis.enrichment) {
      drawEnrichment(data.analysis.enrichment);
    }
    setStatus("Report ready — copy it from the bottom panel.");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("reportBtn").disabled = false;
  }
});
