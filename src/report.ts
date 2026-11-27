// Security Readiness Report: a Markdown summary of one repository scan. Built only from the scan result, the
// dependency map and the change diff. Evidence passes through the existing redactor, and no message text is included.
import type { ScanResult } from "./scanner/scan";
import type { Severity } from "./scanner/rules";
import type { DependencyMap } from "./deps";
import type { ScanDiff } from "./snapshots";
import { createRedactor, type Redactor } from "./redact";

export interface ReportInput {
  slug: string; commit?: string; scannedAt: number; scan: ScanResult;
  deps?: DependencyMap; diff?: ScanDiff; changeNote?: string;
}

const SEV: Severity[] = ["critical", "high", "medium", "low"];
const VERDICT: Record<string, string> = {
  "do-not-run": "Do not run this project",
  "review-first": "Review before running anything",
  incomplete: "Incomplete scan — not a safety result",
  "no-known-indicators": "No known indicators found — not proof of safety",
};
const MAX_PER_SEVERITY = 40;
const iso = (t: number) => new Date(t).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
/** Markdown-safe inline text: no table or heading breakage, no raw HTML. */
const md = (s: string) => s.replace(/[\\`*_[\]|#]/g, (c) => "\\" + c).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\s+/g, " ").trim();
/** Inside a code span HTML is inert and backslashes are literal, so only backticks need replacing. */
const span = (s: string) => "`" + s.replace(/`/g, "'").replace(/\s+/g, " ") + "`";
/** Evidence is shown as code, after redaction, so tokens and keys never reach the file. */
let redactor: Redactor = createRedactor();
/** One redactor per report, so the same value always gets the same placeholder and different values never share one. */
const code = (s: string) => { const t = redactor.redact(s).replace(/`/g, "'").replace(/\s+/g, " ").trim(); return "`" + (t.length > 200 ? t.slice(0, 200) + "…" : t) + "`"; };

export function buildReport(r: ReportInput): string {
  redactor = createRedactor();
  const { scan } = r;
  const L: string[] = [];
  L.push(`# Decoy security readiness report`, ``);
  L.push(`- **Repository:** github.com/${md(r.slug)}`);
  if (r.commit) L.push(`- **Commit:** ${md(r.commit)}`);
  L.push(`- **Scanned:** ${iso(r.scannedAt)}`);
  L.push(`- **Verdict:** ${VERDICT[scan.verdict] ?? md(scan.verdict)}`);
  L.push(`- **Coverage:** ${scan.filesScanned} files inspected${scan.assetsNotInspected ? `, ${scan.assetsNotInspected} media files not inspected` : ""}${scan.complete ? ", complete" : `, **incomplete** (${scan.issues.length} item(s) could not be inspected)`}`);
  L.push(``, `## Summary`, ``);
  L.push(`Findings: ${SEV.map((s) => `${scan.counts[s]} ${s}`).join(", ")}.`);
  if (scan.verdict === "no-known-indicators") L.push(``, `No known indicators were found by Decoy's rules. This is not a statement that the repository is safe or secure.`);
  if (!scan.complete) L.push(``, `Because the scan is incomplete, the absence of a finding in an uninspected file means nothing.`);

  L.push(``, `## Findings by severity`);
  if (!scan.findings.length) L.push(``, `None.`);
  for (const s of SEV) {
    const list = scan.findings.filter((f) => f.severity === s);
    if (!list.length) continue;
    L.push(``, `### ${s[0].toUpperCase() + s.slice(1)} (${list.length})`, ``);
    for (const f of list.slice(0, MAX_PER_SEVERITY)) {
      L.push(`- **${md(f.title)}** — ${span(`${f.file}:${f.line}`)} (${f.ruleId}, ${f.confidence} confidence)`);
      L.push(`  - Evidence: ${code(f.evidence)}`);
      L.push(`  - Why it matters: ${md(f.explanation)}`);
      L.push(`  - Next step: ${md(f.remediation)}`);
    }
    if (list.length > MAX_PER_SEVERITY) L.push(`- …and ${list.length - MAX_PER_SEVERITY} more ${s} findings (see the Decoy panel).`);
  }

  if (scan.issues.length) {
    L.push(``, `## Not inspected`, ``);
    for (const x of scan.issues.slice(0, 30)) L.push(`- ${md(x.kind)}${x.path ? ` — ${span(x.path)}` : ""}: ${md(x.detail)}`);
    if (scan.issues.length > 30) L.push(`- …and ${scan.issues.length - 30} more.`);
  }

  L.push(``, `## Dependency risks`, ``);
  if (!r.deps || !r.deps.manifests.length) L.push(`No dependency data available: no package.json was found in the files scanned. This does not mean the project has no dependencies; only npm package.json files are mapped.`);
  else if (!r.deps.deps.length && r.deps.manifests.every((m) => m.state === "parsed")) L.push(`The package.json file(s) declare no dependencies in the sections Decoy reads. Dependencies installed another way would not appear here; only npm package.json files are mapped.`);
  else {
    const d = r.deps;
    const flagged = d.deps.filter((x) => x.status === "flagged");
    const unknown = d.deps.filter((x) => x.status === "not-analysed");
    L.push(`${d.deps.length} direct dependencies declared in ${d.manifests.length} package.json file(s). ${flagged.length} flagged, ${d.deps.length - flagged.length - unknown.length} with no finding for their declared source, ${unknown.length} not analysed.`);
    for (const m of d.manifests.filter((m) => m.state === "unparseable")) L.push(`- ${span(m.path)} could not be parsed; its dependencies are unknown.`);
    for (const x of flagged) L.push(`- **${md(x.name)}** (${md(x.section)} in ${span(x.manifest)}): ${x.findings.map((f) => `${f.severity} — ${md(f.title)}`).join("; ")}. Declared as ${code(x.spec)}`);
    for (const f of d.lockfileFindings) L.push(`- Lockfile ${span(`${f.file}:${f.line}`)}: ${f.severity} — ${md(f.title)}`);
    L.push(``, `Only each dependency's declared source is checked. Package contents and transitive dependencies are not analysed.`);
  }

  L.push(``, `## Changes since the previous scan`, ``);
  if (r.diff) {
    const x = r.diff;
    L.push(`Previous scan: ${iso(x.previousAt)}${x.previousCommit ? ` (commit ${md(x.previousCommit.slice(0, 12))})` : ""}. Current scan: ${iso(x.currentAt)}${x.currentCommit ? ` (commit ${md(x.currentCommit.slice(0, 12))})` : ""}.`, ``);
    L.push(`- New findings: ${x.added.length}`, `- Resolved: ${x.resolved.length}`, `- Changed: ${x.changed.length}`);
    if (x.notRechecked.length) L.push(`- Not rechecked (file not inspected this time): ${x.notRechecked.length}`);
    for (const f of x.added.filter((f) => f.severity !== "low").slice(0, 20)) L.push(`  - New: ${f.severity} — ${md(f.title)} at ${span(`${f.file}:${f.line}`)}`);
    if (x.newRiskyFiles.length) L.push(`- New files with findings: ${x.newRiskyFiles.map(span).join(", ")}`);
    if (x.addedDeps.length) L.push(`- Dependencies added: ${x.addedDeps.length}`);
    if (x.removedDeps.length) L.push(`- Dependencies removed: ${x.removedDeps.length}`);
    for (const n of x.notes) L.push(`- ${md(n)}`);
    L.push(``, `A new finding is not proof of malicious intent; it is something to review.`);
  } else L.push(md(r.changeNote ?? "No previous scan of this repository on this device."));

  L.push(``, `## Recommended next steps`, ``);
  const steps: string[] = [];
  if (scan.verdict === "do-not-run") steps.push("Do not run, install or build this project, and don't open it in an editor that runs tasks automatically.");
  const files = [...new Set(scan.findings.filter((f) => f.severity === "critical" || f.severity === "high").map((f) => `${f.file}:${f.line}`))].slice(0, 5);
  if (files.length) steps.push(`Review ${files.map(span).join(", ")}.`);
  if (scan.findings.some((f) => f.category === "Automatic execution")) steps.push("If you must install, use `npm install --ignore-scripts` after reading the scripts.");
  if (r.deps?.deps.some((d) => d.status === "flagged")) steps.push("Check the source of each flagged dependency before installing.");
  if (!scan.complete) steps.push("Inspect the files Decoy could not read before relying on this report.");
  if (scan.verdict === "do-not-run" || scan.verdict === "review-first") steps.push(`Verify that github.com/${md(r.slug.split("/")[0])} is who you expect.`);
  if (!steps.length) steps.push("Read the package.json scripts and setup instructions before installing. No rule-based finding is not a guarantee.");
  for (const s of steps) L.push(`- ${s}`);

  L.push(``, `## Scope and limitations`, ``);
  L.push(`- Decoy read the repository's files from GitHub at the commit above. Nothing was installed, built or run.`);
  L.push(`- Findings come from pattern-matching rules. They can miss malicious code and can flag harmless code.`);
  L.push(`- Evidence lines are shortened and passed through redaction; check the original file for full context.`);
  L.push(`- Generated on this device by Decoy. This report was not sent anywhere.`);
  return L.join("\n") + "\n";
}

export const reportFilename = (slug: string, at: number) => `decoy-report-${slug.replace(/[^\w.-]+/g, "_")}-${new Date(at).toISOString().slice(0, 10)}.md`;
