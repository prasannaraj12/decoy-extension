import { askLocal, askCloud, testCloud, localModelStatus, prepareLocalModel, LocalUnavailableError, type AIResult } from "./ai/hybrid";
import { approve } from "./ai/consent";
import { describeLocalStatus } from "./ai/status";
import { messagePrompt, findingPrompt, cloudPayload, SEED_PHRASE_WARNING } from "./ai/prompts";
import { scanMessage, extractLinks, assessMessage, type MessageSignal, type LinkedRepo, type ConcernLevel } from "./scanner/message";
import { scanFiles, type ScanResult } from "./scanner/scan";
import { fetchRepo, parseRepoUrl } from "./scanner/github";
import { Investigation } from "./timeline";
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
/** Every repository scanned in this panel, for linking back to the message that pointed at it. */
const repoResults = new Map<string, LinkedRepo>();
let shownLevel: ConcernLevel | undefined;
const LEVEL: Record<ConcernLevel, [string, string]> = { high: ["critical", "High concern"], "worth-checking": ["medium", "Worth checking"], low: ["low", "Low concern"] };

/** The combined view of the current message, including any repository it links to that has been scanned. */
function currentAssessment() {
  const linked = lastMessage ? extractLinks(lastMessage).repos.map((r) => repoResults.get(r)).filter((r): r is LinkedRepo => !!r) : [];
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
  lastScan = undefined; lastRepo = undefined; clearCloud();
  $<HTMLButtonElement>("scanRepo").disabled = true;
  let top: ScanResult["findings"] = [];
  try {
    const { files, issues, assetsNotInspected, slug } = await fetchRepo(url, (d, t) => ($("repoOut").textContent = `Fetched ${d}/${t} files…`));
    lastScan = scanFiles(files, { issues, assetsNotInspected }); lastRepo = slug;
    const scan = lastScan;
    inv.scannedRepos.add(slug);
    repoResults.set(slug, { slug, verdict: lastScan.verdict, complete: lastScan.complete });
    const [cls, label] = VERDICT[lastScan.verdict];
    inv.add({ kind: "repo", source: "rules", title: `Repository scanned: ${label}${scan.complete ? "" : " (incomplete)"}`, detail: `${slug} · ${lastScan.counts.critical} critical, ${lastScan.counts.high} high, ${lastScan.counts.medium} medium` });
    renderTimeline();
    renderAssessment(); // a linked repo rated "do not run" raises the message's assessment

    $("repoOut").innerHTML = `<div class="verdict ${cls}">${label}</div>
      <div class="muted">${lastScan.filesScanned} files scanned · ${lastScan.counts.critical} critical · ${lastScan.counts.high} high · ${lastScan.counts.medium} medium${scan.assetsNotInspected ? ` · ${scan.assetsNotInspected} media files not inspected` : ""}</div>` +
      (scan.complete ? "" : `<div class="finding"><b class="medium">Incomplete: ${scan.issues.length} item(s) could not be inspected</b>${scan.issues.slice(0, 10).map((x) => `<br><span class="muted">${esc(x.kind)}${x.path ? " · " + esc(x.path) : ""} · ${esc(x.detail)}</span>`).join("")}${scan.issues.length > 10 ? `<br><span class="muted">…and ${scan.issues.length - 10} more</span>` : ""}</div>`) +
      lastScan.findings.map((f, i) => `<div class="finding"><b class="${f.severity}">[${f.severity}] ${esc(f.title)}</b> <span class="muted">${esc(f.file)}:${f.line}</span>
        <code>${esc(f.evidence)}</code><span class="muted">${esc(f.explanation)} <b>Do:</b> ${esc(f.remediation)} (${f.ruleId} · ${f.confidence} confidence)</span>
        ${i < 5 ? `<div id="ai-${i}" class="muted">Explaining on-device…</div>` : ""}</div>`).join("");

    top = scan.findings.slice(0, 5);
  } catch (e: any) {
    $("repoOut").innerHTML = `<span class="badge unknown">Scan failed — not a safety result</span> ${esc(e?.message ?? String(e))}`;
    inv.add({ kind: "repo", source: "rules", title: "Repository scan failed: no result", detail: url });
    renderTimeline();
  } finally { $<HTMLButtonElement>("scanRepo").disabled = false; } // results are in; explanations follow
  // Nano explains the top 5 findings, one at a time (small context window).
  for (let i = 0; i < top.length; i++) {
    const ai = await localOrExplain(findingPrompt(top[i]));
    if (run !== repoRun) return;
    $(`ai-${i}`).outerHTML = ai;
  }
};

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

refreshStatus().then((done) => { if (!done) pollStatus(); });
takePending();
