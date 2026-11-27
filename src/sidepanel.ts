import { askLocal, askCloud, testCloud, localModelStatus, prepareLocalModel, LocalUnavailableError, type AIResult } from "./ai/hybrid";
import { approve } from "./ai/consent";
import { describeLocalStatus } from "./ai/status";
import { messagePrompt, findingPrompt, cloudPayload, SEED_PHRASE_WARNING } from "./ai/prompts";
import { scanMessage, extractLinks, assessMessage, type MessageSignal, type LinkedRepo, type ConcernLevel } from "./scanner/message";
import { scanFiles, type ScanResult } from "./scanner/scan";
import { fetchRepo, parseRepoUrl } from "./scanner/github";
import { Investigation } from "./timeline";
import { buildInvestigation, type RepoRecord } from "./investigation";
import { makeSnapshot, loadSnapshot, saveSnapshot, diffSnapshots, chromeLocal, type ScanDiff } from "./snapshots";
import { buildDependencyMap, sortDeps, type DependencyMap, type Dependency } from "./deps";
import { buildReport, reportFilename, type ReportInput } from "./report";
import { hasSeedPhrase } from "./redact";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const badge = (src: string) => `<span class="badge ${src}">${src === "on_device" ? "On-device · Gemini Nano" : src === "in_cloud" ? "Cloud · Gemini" : src}</span>`;
const aiBlock = (r: AIResult) => `<div class="ai">${badge(r.source)} <span class="muted">${r.ms} ms</span>\n${esc(r.text)}</div>`;

const inv = new Investigation();
let lastSignals: MessageSignal[] = [];
let lastMessage: string | undefined;
let lastScan: ScanResult | undefined;
let lastRepo: string | undefined;
/** Every repository scanned in this panel (or whose scan failed), for linking back to the message that pointed at it. */
const repoRecords = new Map<string, RepoRecord>();
let shownLevel: ConcernLevel | undefined;
const LEVEL: Record<ConcernLevel, [string, string]> = { high: ["critical", "High concern"], "worth-checking": ["medium", "Worth checking"], low: ["low", "Low concern"] };

/** The combined view of the current message, including any repository it links to that has been scanned. */
function currentAssessment() {
  const linked = lastMessage ? extractLinks(lastMessage).repos.flatMap((s): LinkedRepo[] => { const r = repoRecords.get(s); return r && "scan" in r ? [{ slug: s, verdict: r.scan.verdict, complete: r.scan.complete }] : []; }) : [];
  return assessMessage(lastSignals, { seedPhrase: !!lastMessage && hasSeedPhrase(lastMessage), linkedRepos: linked });
}
function renderAssessment() {
  const el = document.getElementById("msgAssess");
  if (!el || !lastMessage) return;
  const a = currentAssessment();
  const [cls, label] = LEVEL[a.level];
  el.innerHTML = `<div class="verdict ${cls}">${label}</div><p>${esc(a.summary.replace(/^[^.]*\.\s*/, ""))}</p>` +
    (a.reasons.length ? `<ul>${a.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : "") +
    `<p class="muted">This describes the message, not the person who sent it.</p>`;
  if (shownLevel && shownLevel !== a.level) {
    inv.add({ kind: "message", source: "rules", title: `Message assessment changed to ${label.toLowerCase()}`, detail: a.reasons.at(-1) });
    renderTimeline();
  }
  shownLevel = a.level;
}

const LEVEL_CLS: Record<ConcernLevel, string> = { high: "critical", "worth-checking": "medium", low: "low" };
const STATE: Record<string, [string, string]> = { "not-scanned": ["rules", "not scanned"], failed: ["unknown", "scan failed"], "do-not-run": ["sev-critical", "do not run"], "review-first": ["sev-high", "review first"], incomplete: ["unknown", "incomplete"], "no-known-indicators": ["rules", "no known indicators"] };
/** The combined view: message evidence, linked repository evidence, how the level was decided, and what to do next. */
function renderInvestigation() {
  const el = $("investigationOut");
  if (!lastMessage && !repoRecords.size) { el.innerHTML = `<p class="muted">Scan a message, a repository, or both. A repository linked from the message is counted with it.</p>`; return; }
  const v = buildInvestigation({ message: lastMessage, signals: lastSignals, seedPhrase: !!lastMessage && hasSeedPhrase(lastMessage), repos: repoRecords });
  const ev = (from: "message" | "repository", repo?: string) => v.evidence.filter((e) => e.from === from && (!repo || e.repo === repo));
  const list = (items: typeof v.evidence) => items.length
    ? `<ul class="ev">${items.map((e) => `<li><b class="${e.strong ? "high" : "low"}">${esc(e.title)}</b>${e.where ? ` <span class="muted">${esc(e.where)}</span>` : ""}</li>`).join("")}</ul>`
    : `<p class="muted">No warning signs from this source.</p>`;
  const msgPart = lastMessage
    ? `<div class="src"><div class="src-h"><span class="tag">From the message</span> <span class="muted">${v.messageLevel ? "on its own: " + LEVEL[v.messageLevel][1].toLowerCase() : ""}</span></div>${list(ev("message"))}</div>`
    : "";
  const repoParts = (lastMessage ? v.links.map((l) => l.slug) : v.unlinked).map((slug) => {
    const link = v.links.find((l) => l.slug === slug);
    const r = repoRecords.get(slug);
    const state = link?.state ?? (r && "scan" in r ? r.scan.verdict : r ? "failed" : "not-scanned");
    const [cls, text] = STATE[state];
    return `<div class="src"><div class="src-h"><span class="tag">From the repository</span> <b>${esc(slug)}</b> <span class="badge ${cls}">${text}</span></div>${link ? `<p class="effect">${esc(link.effect)}</p>` : ""}${r && "scan" in r ? list(ev("repository", slug)) : ""}</div>`;
  }).join("");
  const noLink = lastMessage && !v.links.length ? `<p class="muted">No GitHub repository link in this message, so the assessment is based on the message alone.</p>` : "";
  el.innerHTML = `<div class="verdict ${LEVEL_CLS[v.level]}">${LEVEL[v.level][1]}</div>
    <h3>Evidence</h3>${msgPart}${repoParts}${noLink}
    <h3>How this level was decided</h3><ol class="decided">${v.decided.map((d) => `<li>${esc(d)}</li>`).join("")}</ol>
    <h3>Next steps</h3><ul class="actions">${v.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>`;
}

function renderTimeline() {
  $("timeline").innerHTML = inv.events.length
    ? inv.events.map((e) => `<li class="${e.kind}"><span class="muted">${new Date(e.at).toLocaleTimeString()}</span> ${e.source ? badge(e.source) : ""}<br><b>${esc(e.title)}</b>${e.detail ? `<br><span class="muted">${esc(e.detail)}</span>` : ""}</li>`).join("")
    : `<li class="muted">Nothing yet.</li>`;
}

/** If on-device isn't available, say so honestly — never silently fall back with private text. */
async function localOrExplain(prompt: string): Promise<string> {
  try { return aiBlock(await askLocal(prompt)); }
  catch (e: any) {
    const detail = `Rule-based findings above still apply. (${esc(e?.message ?? String(e))})`;
    return e instanceof LocalUnavailableError
      ? `<div class="ai"><span class="badge unknown">On-device unavailable</span>\nNothing was sent anywhere. ${detail}</div>`
      : `<div class="ai"><span class="badge unknown">On-device analysis failed</span>\nNo result was accepted. The local-only model has no network endpoint. ${detail}</div>`;
  }
}

// ---------- Hybrid status ----------
let preparing = false;
let polls = 0;
/** Chrome can take several seconds to notice an installed model, so re-check for two minutes or until it is available. */
function pollStatus() {
  if (polls++ >= 24) return;
  setTimeout(async () => { if (!preparing && !(await refreshStatus())) pollStatus(); }, 5000);
}
async function refreshStatus(note?: string): Promise<boolean> {
  const status = await localModelStatus();
  const v = describeLocalStatus(status);
  if (preparing) return false; // don't overwrite download progress
  $("nanoStatus").textContent = v.label;
  $("nanoProgress").textContent = note ?? v.detail;
  const b = $<HTMLButtonElement>("prepNano");
  b.textContent = v.button; b.disabled = !v.canPrepare;
  return status === "available" || status === "no-api" || status === "unavailable";
}
$("prepNano").onclick = async () => {
  $<HTMLButtonElement>("prepNano").disabled = true;
  $("nanoStatus").textContent = "Preparing…";
  let note: string | undefined;
  preparing = true;
  try {
    await prepareLocalModel((p) => {
      $("nanoStatus").textContent = describeLocalStatus("downloading").label;
      $("nanoProgress").textContent = `Downloading model… ${Math.round(p * 100)}%`;
    });
  } catch (e: any) { note = "Preparation failed: " + (e?.message ?? e); }
  finally { preparing = false; }
  await refreshStatus(note);
};
let testRun = 0;
$("testLocal").onclick = async () => {
  const run = ++testRun;
  $("testOut").innerHTML = "Running on-device…";
  let html: string;
  try { html = aiBlock(await askLocal("Reply with one short sentence confirming you are running.")); }
  catch (e: any) { html = `<span class="badge unknown">failed</span> ${esc(e?.message ?? String(e))}`; }
  if (run === testRun) $("testOut").innerHTML = html;
  refreshStatus();
};
$("testCloud").onclick = async () => {
  const run = ++testRun;
  $("testOut").innerHTML = "Calling cloud…";
  let html: string;
  try { html = aiBlock(await testCloud()); }
  catch (e: any) { html = `<span class="badge unknown">failed</span> ${esc(e?.message ?? String(e))}`; }
  if (run === testRun) $("testOut").innerHTML = html;
};

// ---------- 1. Message ----------
/** Identifies the latest scan, so a slow reply about an earlier message or repo is dropped. */
let msgRun = 0, repoRun = 0;
$("scanMsg").onclick = async () => {
  const text = $<HTMLTextAreaElement>("msg").value.trim();
  if (!text) return;
  const run = ++msgRun;
  lastSignals = scanMessage(text); lastMessage = text;
  clearCloud(); // an open preview no longer describes the current evidence
  extractLinks(text).repos.forEach((r) => inv.messageRepos.add(r));
  shownLevel = undefined;
  const level = LEVEL[currentAssessment().level][1];
  inv.add({ kind: "message", source: "rules", title: `Message scanned: ${level.toLowerCase()} (${lastSignals.length} signal${lastSignals.length === 1 ? "" : "s"})`, detail: lastSignals.map((s) => s.title).join(" · ") });
  const repos = extractLinks(text).repos;
  if (repos[0] && !$<HTMLInputElement>("repo").value) $<HTMLInputElement>("repo").value = `https://github.com/${repos[0]}`;

  const seed = hasSeedPhrase(text) ? `<div class="verdict critical">Possible seed phrase</div><p>${esc(SEED_PHRASE_WARNING)}</p>` : "";
  $("msgOut").innerHTML = seed + `<div id="msgAssess"></div>` + (lastSignals.length
    ? lastSignals.map((s) => `<div class="finding"><b class="${s.weight === "strong" ? "high" : "low"}">${esc(s.title)}</b> <span class="muted">${s.weight === "strong" ? "strong signal" : "common in normal work"}</span><code>${esc(s.quote)}</code><span class="muted">${esc(s.why)}</span></div>`).join("")
    : "") + `<div class="muted">Explaining on-device…</div>`;
  renderAssessment();
  renderTimeline();
  renderInvestigation();
  const ai = await localOrExplain(messagePrompt(text, lastSignals));
  if (run === msgRun) $("msgOut").lastElementChild!.outerHTML = ai;
};

// ---------- 2. Repository ----------
const VERDICT = { "do-not-run": ["critical", "Do not run this project"], "review-first": ["high", "Review before running anything"], incomplete: ["medium", "Incomplete scan — not a safety result"], "no-known-indicators": ["low", "No known indicators found — not proof of safety"] } as const;

$("scanRepo").onclick = async () => {
  const url = $<HTMLInputElement>("repo").value.trim();
  if (!url) return;
  const run = ++repoRun;
  $("repoOut").innerHTML = "Fetching files (nothing is executed)…";
  // Forget the previous repo first, so a failed scan can't be reported with its results.
  lastScan = undefined; lastRepo = undefined; reportInput = undefined; clearCloud();
  $<HTMLButtonElement>("scanRepo").disabled = true;
  let top: ScanResult["findings"] = [];
  try {
    const { files, issues, assetsNotInspected, slug, commit } = await fetchRepo(url, (d, t) => ($("repoOut").textContent = `Fetched ${d}/${t} files…`));
    lastScan = scanFiles(files, { issues, assetsNotInspected }); lastRepo = slug;
    const scan = lastScan;
    inv.scannedRepos.add(slug);
    repoRecords.set(slug, { slug, scan });
    const [cls, label] = VERDICT[lastScan.verdict];
    inv.add({ kind: "repo", source: "rules", title: `Repository scanned: ${label}${scan.complete ? "" : " (incomplete)"}`, detail: `${slug} · ${lastScan.counts.critical} critical, ${lastScan.counts.high} high, ${lastScan.counts.medium} medium` });
    renderTimeline();
    renderAssessment(); // a linked repo rated "do not run" raises the message's assessment
    renderInvestigation();

    $("repoOut").innerHTML = `<div class="verdict ${cls}">${label}</div>
      <div class="muted">${lastScan.filesScanned} files scanned · ${lastScan.counts.critical} critical · ${lastScan.counts.high} high · ${lastScan.counts.medium} medium${scan.assetsNotInspected ? ` · ${scan.assetsNotInspected} media files not inspected` : ""}</div>
      <div class="row"><button id="reportBtn" class="ghost" disabled>Download readiness report (.md)</button></div>
      <div id="repoChanges" class="sub-block"><h3>Changes since last scan</h3><p class="muted">Comparing with the saved snapshot…</p></div>
      <div id="repoDeps" class="sub-block"></div>
      <h3 class="findings-h">Findings</h3>` +
      (scan.complete ? "" : `<div class="finding"><b class="medium">Incomplete: ${scan.issues.length} item(s) could not be inspected</b>${scan.issues.slice(0, 10).map((x) => `<br><span class="muted">${esc(x.kind)}${x.path ? " · " + esc(x.path) : ""} · ${esc(x.detail)}</span>`).join("")}${scan.issues.length > 10 ? `<br><span class="muted">…and ${scan.issues.length - 10} more</span>` : ""}</div>`) +
      lastScan.findings.map((f, i) => `<div class="finding"><b class="${f.severity}">[${f.severity}] ${esc(f.title)}</b> <span class="muted">${esc(f.file)}:${f.line}</span>
        <code>${esc(f.evidence)}</code><span class="muted">${esc(f.explanation)} <b>Do:</b> ${esc(f.remediation)} (${f.ruleId} · ${f.confidence} confidence)</span>
        ${i < 5 ? `<div id="ai-${i}" class="muted">Explaining on-device…</div>` : ""}</div>`).join("");

    top = scan.findings.slice(0, 5);

    // Dependency map, change detection and report: all on this device. Snapshots go to chrome.storage.local only.
    const now = Date.now();
    const deps = buildDependencyMap(files, scan.findings);
    renderDeps(deps);
    const snap = await makeSnapshot(slug, scan, files.map((f) => f.path), deps, { commit, now });
    const prev = await loadSnapshot(chromeLocal(), slug);
    if (run !== repoRun) return;
    let diff: ScanDiff | undefined, changeNote: string | undefined;
    const saved = await saveSnapshot(chromeLocal(), snap);
    const savedNote = saved.ok ? "This scan is saved on this device for next time." : `This scan could not be saved (${saved.message}), so the next scan can't be compared with it.`;
    if (prev.state === "found") { diff = diffSnapshots(prev.snapshot, snap, new Set(scan.issues.map((x) => x.path))); renderChanges({ diff }, savedNote); }
    else if (prev.state === "none") { changeNote = "First scan of this repository on this device."; renderChanges({ first: true }, savedNote); }
    else { changeNote = prev.state === "unreadable" ? "The saved snapshot is from an older or unreadable format, so it was not compared." : `The saved snapshot could not be read (${prev.message}).`; renderChanges({ note: changeNote }, savedNote); }
    if (run !== repoRun) return;
    if (diff) inv.add({ kind: "repo", source: "rules", title: `Changes since ${new Date(diff.previousAt).toLocaleDateString()}: ${diff.added.length} new, ${diff.resolved.length} resolved, ${diff.changed.length} changed`, detail: slug });
    renderTimeline();
    reportInput = { slug, commit, scannedAt: now, scan, deps, diff, changeNote };
    const btn = $<HTMLButtonElement>("reportBtn");
    btn.disabled = false; btn.onclick = downloadReport;
  } catch (e: any) {
    $("repoOut").innerHTML = `<span class="badge unknown">Scan failed — not a safety result</span> ${esc(e?.message ?? String(e))}`;
    inv.add({ kind: "repo", source: "rules", title: "Repository scan failed: no result", detail: url });
    const ref = parseRepoUrl(url);
    if (ref) { const slug = `${ref.owner}/${ref.repo}`.toLowerCase(); repoRecords.set(slug, { slug, failed: String(e?.message ?? e) }); }
    renderTimeline();
    renderInvestigation();
  } finally { $<HTMLButtonElement>("scanRepo").disabled = false; } // results are in; explanations follow
  // Nano explains the top 5 findings, one at a time (small context window).
  for (let i = 0; i < top.length; i++) {
    const ai = await localOrExplain(findingPrompt(top[i]));
    if (run !== repoRun) return;
    $(`ai-${i}`).outerHTML = ai;
  }
};

// ---------- Risky changes, dependency map, report ----------
const fmt = (t: number) => new Date(t).toLocaleString();
let reportInput: ReportInput | undefined;

function renderChanges(state: { diff: ScanDiff } | { first: true } | { note: string }, saved: string) {
  const el = $("repoChanges");
  if (!el) return;
  if ("note" in state) { el.innerHTML = `<h3>Changes since last scan</h3><p class="muted">${esc(state.note)} ${esc(saved)}</p>`; return; }
  if ("first" in state) { el.innerHTML = `<h3>Changes since last scan</h3><p class="muted">First scan of this repository on this device, so there is nothing to compare yet. ${esc(saved)}</p>`; return; }
  const d = state.diff;
  const item = (f: { severity: string; title: string; file: string; line: number }) => `<li><b class="${f.severity}">[${esc(f.severity)}] ${esc(f.title)}</b> <span class="muted">${esc(f.file)}:${f.line}</span></li>`;
  const block = (title: string, items: string[], cap = 15) => items.length ? `<p class="sub">${title} (${items.length})</p><ul class="ev">${items.slice(0, cap).join("")}${items.length > cap ? `<li class="muted">…and ${items.length - cap} more</li>` : ""}</ul>` : "";
  const nothing = !d.added.length && !d.resolved.length && !d.changed.length && !d.notRechecked.length && !d.addedDeps.length && !d.removedDeps.length;
  el.innerHTML = `<h3>Changes since last scan</h3>
    <p class="muted">Previous: ${esc(fmt(d.previousAt))}${d.previousCommit ? ` · ${esc(d.previousCommit.slice(0, 7))}` : ""}<br>Current: ${esc(fmt(d.currentAt))}${d.currentCommit ? ` · ${esc(d.currentCommit.slice(0, 7))}` : ""}</p>
    <div class="chips"><span class="chip">${d.added.length} new</span><span class="chip">${d.resolved.length} resolved</span><span class="chip">${d.changed.length} changed</span>${d.notRechecked.length ? `<span class="chip">${d.notRechecked.length} not rechecked</span>` : ""}</div>` +
    (nothing ? `<p class="muted">No differences in findings or declared dependencies.</p>` : "") +
    (d.newRiskyFiles.length ? `<p class="sub">New files with findings</p><ul class="ev">${d.newRiskyFiles.map((f) => `<li><b>${esc(f)}</b></li>`).join("")}</ul>` : "") +
    block("New findings", d.added.map(item)) +
    block("Changed", d.changed.map((c) => `<li><b class="${c.after.severity}">${esc(c.after.title)}</b> <span class="muted">${esc(c.after.file)} · ${esc(c.what.join(", "))}</span></li>`)) +
    block("Resolved", d.resolved.map(item)) +
    block("Not rechecked (file not inspected this time)", d.notRechecked.map(item)) +
    block("Dependencies added", d.addedDeps.map((x) => `<li>${esc(x)}</li>`)) +
    block("Dependencies removed", d.removedDeps.map((x) => `<li>${esc(x)}</li>`)) +
    d.notes.map((n) => `<p class="muted">${esc(n)}</p>`).join("") +
    `<p class="muted">New does not mean malicious. Review new findings like any other. ${esc(saved)}</p>`;
}

const DEP_STATUS: Record<Dependency["status"], [string, string]> = { flagged: ["sev-high", "flagged"], "source-checked": ["rules", "source checked"], "not-analysed": ["unknown", "not analysed"] };
const DEP_PAGE = 150;
function renderDeps(map: DependencyMap, showAll = false) {
  const el = $("repoDeps");
  if (!el) return;
  const scope = "Decoy maps npm dependencies declared in package.json only. Other package managers (pip, Maven, Go, Cargo and so on) are not mapped.";
  if (!map.manifests.length) { el.innerHTML = `<h3>Dependency map</h3><p class="muted">No dependency data available: no package.json was found in the files scanned. This does not mean the project has no dependencies. ${scope}</p>`; return; }
  const flagged = map.deps.filter((d) => d.status === "flagged").length;
  const unknown = map.deps.filter((d) => d.status === "not-analysed").length;
  const row = (d: Dependency) => {
    const [cls, label] = DEP_STATUS[d.status];
    const head = `<span class="dep-name">${esc(d.name)}</span> <span class="muted">${esc(d.section)}</span> <span class="badge ${cls}">${label}</span>`;
    const body = d.status === "flagged"
      ? d.findings.map((f) => `<div class="finding"><b class="${f.severity}">[${f.severity}] ${esc(f.title)}</b> <span class="muted">${esc(f.file)}:${f.line}</span><code>${esc(f.evidence)}</code><span class="muted">${esc(f.explanation)} <b>Do:</b> ${esc(f.remediation)}</span></div>`).join("")
      : d.status === "not-analysed" ? `<p class="muted">This entry isn't a version string, so its source could not be checked.</p>`
      : `<p class="muted">Declared as <code class="inline">${esc(d.spec)}</code>. No finding for this source. The package's own code was not analysed.</p>`;
    return `<li><details><summary>${head}</summary>${body}</details></li>`;
  };
  const groups = map.manifests.map((m) => {
    if (m.state === "unparseable") return `<li class="mf"><b>${esc(m.path)}</b> <span class="badge unknown">could not be parsed</span><p class="muted">Its dependencies are unknown.</p></li>`;
    const all = sortDeps(map.deps.filter((d) => d.manifest === m.path));
    const shown = showAll ? all : all.slice(0, DEP_PAGE);
    return `<li class="mf"><b>${esc(m.path)}</b>${m.name ? ` <span class="muted">${esc(m.name)}</span>` : ""} <span class="muted">· ${all.length} direct</span>
      ${all.length ? `<ul class="deps">${shown.map(row).join("")}</ul>` : `<p class="muted">This package.json declares no dependencies in any section Decoy reads. Dependencies installed another way (for example by a setup script or another package manager) would not appear here.</p>`}
      ${shown.length < all.length ? `<p class="muted">${all.length - shown.length} more not shown, none flagged.</p>` : ""}</li>`;
  }).join("");
  const lock = map.lockfileFindings.length
    ? `<p class="sub">Lockfile sources outside the npm registry (${map.lockfileFindings.length})</p><ul class="ev">${map.lockfileFindings.slice(0, 20).map((f) => `<li><b class="${f.severity}">[${f.severity}]</b> <span class="muted">${esc(f.file)}:${f.line}</span></li>`).join("")}</ul><p class="muted">Not linked to a package name: Decoy doesn't parse the lockfile into a tree.</p>` : "";
  const more = !showAll && map.manifests.some((m) => map.deps.filter((d) => d.manifest === m.path).length > DEP_PAGE);
  el.innerHTML = `<h3>Dependency map</h3>
    <p class="muted">${map.deps.length} direct dependencies in ${map.manifests.length} package.json file(s) · <span class="${flagged ? "high" : ""}">${flagged} flagged</span> · ${unknown} not analysed. Transitive dependencies and package contents are not analysed. ${scope}</p>
    <ul class="tree"><li class="root"><b>${esc(lastRepo ?? "repository")}</b><ul class="tree">${groups}</ul></li></ul>${lock}
    ${more ? `<button id="depsAll" class="ghost">Show all dependencies</button>` : ""}`;
  if (more) $("depsAll").onclick = () => renderDeps(map, true);
}

function downloadReport() {
  if (!reportInput) return;
  const url = URL.createObjectURL(new Blob([buildReport(reportInput)], { type: "text/markdown" }));
  const a = document.createElement("a");
  a.href = url; a.download = reportFilename(reportInput.slug, reportInput.scannedAt);
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------- 4. Consent-gated cloud ----------
function clearCloud() { $("cloudPreview").innerHTML = ""; }
$("previewCloud").onclick = () => {
  if (!lastSignals.length && !lastScan) { $("cloudPreview").innerHTML = `<p class="muted">Scan a message or repo first.</p>`; return; }
  const name = $<HTMLInputElement>("myName").value.trim();
  const payload = cloudPayload({ message: lastMessage, signals: lastSignals, scan: lastScan, repo: lastRepo, userTerms: name ? name.split(/\s+/).concat(name) : [] });
  if (!payload.ok) { $("cloudPreview").innerHTML = `<p class="critical">${esc(payload.reason)}</p>`; return; }
  const { draft } = payload;
  const redactions = draft.redactions;
  $("cloudPreview").innerHTML = `<p>This exact text will be sent. ${redactions.length} item(s) redacted: ${[...new Set(redactions.map((r) => r.type))].join(", ") || "none"}. The full message and source code are never sent.</p>
    <pre id="cloudText"></pre><button id="sendCloud">I consent — send to cloud</button> <button id="cancelCloud" class="ghost">Cancel</button>`;
  $("cloudText").textContent = draft.text;
  $("cancelCloud").onclick = clearCloud;
  $("sendCloud").onclick = async () => {
    try {
      const approved = approve(draft, $("cloudText").textContent ?? ""); // what is on screen is what is sent
      clearCloud(); $("cloudOut").innerHTML = "Generating report in the cloud…";
      const r = await askCloud(approved);
      inv.add({ kind: "cloud", source: r.source === "in_cloud" ? "in_cloud" : undefined, title: "Cloud incident report generated from redacted evidence" });
      renderTimeline(); $("cloudOut").innerHTML = aiBlock(r);
    } catch (e: any) { $("cloudOut").innerHTML = `<span class="badge unknown">failed</span> ${esc(e?.message ?? String(e))}`; }
  };
};

// ---------- Right-click handoff ----------
async function takePending() {
  const { pending } = (await chrome.storage.session.get("pending")) as { pending?: { text?: string; link?: string } };
  if (!pending) return;
  await chrome.storage.session.remove("pending");
  if (pending.link && parseRepoUrl(pending.link)) $<HTMLInputElement>("repo").value = pending.link;
  if (pending.text) { $<HTMLTextAreaElement>("msg").value = pending.text; $("scanMsg").click(); }
}
chrome.storage.session.onChanged.addListener(takePending);

renderInvestigation();
refreshStatus().then((done) => { if (!done) pollStatus(); });
takePending();
