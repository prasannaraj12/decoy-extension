// Combines a message and the repositories it links to into one investigation: a level, where each piece of evidence
// came from, how the level was decided, and next steps drawn from the evidence. Pure: no network, no DOM.
import { assessMessage, extractLinks, type ConcernLevel, type MessageSignal } from "./scanner/message";
import type { ScanResult } from "./scanner/scan";
import type { Severity } from "./scanner/rules";

/** What is known about one repository in this panel: a scan result, or why there is none. */
export type RepoRecord = { slug: string; scan: ScanResult } | { slug: string; failed: string };

export interface Evidence { from: "message" | "repository"; repo?: string; title: string; where?: string; strong: boolean; }
export interface RepoLink {
  slug: string;
  state: "not-scanned" | "failed" | "do-not-run" | "review-first" | "incomplete" | "no-known-indicators";
  effect: string;
}
export interface InvestigationView {
  level: ConcernLevel;
  /** Present only when a message was scanned. */
  messageLevel?: ConcernLevel;
  links: RepoLink[];
  /** Scanned repositories that this message does not link to. They are shown but never affect the level. */
  unlinked: string[];
  evidence: Evidence[];
  decided: string[];
  actions: string[];
}

const RANK: Record<ConcernLevel, number> = { low: 0, "worth-checking": 1, high: 2 };
const LABEL: Record<ConcernLevel, string> = { low: "low concern", "worth-checking": "worth checking", high: "high concern" };
const IMPORTANT: Severity[] = ["critical", "high"];
const MAX_FILES = 3;

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
const owner = (slug: string) => slug.split("/")[0];

function keyFiles(scan: ScanResult): string[] {
  const files: string[] = [];
  for (const f of scan.findings) if (IMPORTANT.includes(f.severity) && !files.includes(`${f.file}:${f.line}`)) files.push(`${f.file}:${f.line}`);
  return files.slice(0, MAX_FILES);
}

export function buildInvestigation(input: { message?: string; signals?: MessageSignal[]; seedPhrase?: boolean; repos: ReadonlyMap<string, RepoRecord> }): InvestigationView {
  const { message, signals = [], repos } = input;
  const linkedSlugs = message ? extractLinks(message).repos : [];
  const evidence: Evidence[] = [];
  const decided: string[] = [];
  const actions: string[] = [];
  const links: RepoLink[] = [];

  // The message's own level, including the existing rule that a fully scanned "Do not run" repository raises it.
  const linkedRepos = linkedSlugs.flatMap((s) => { const r = repos.get(s); return r && "scan" in r ? [{ slug: s, verdict: r.scan.verdict, complete: r.scan.complete }] : []; });
  const assessment = message ? assessMessage(signals, { seedPhrase: input.seedPhrase, linkedRepos }) : undefined;
  let level: ConcernLevel = assessment?.level ?? "low";
  // The message on its own, so the explanation never credits the message with a level the repository caused.
  const alone = message ? assessMessage(signals, { seedPhrase: input.seedPhrase }) : undefined;

  if (alone) {
    for (const s of signals) evidence.push({ from: "message", title: s.title, strong: s.weight === "strong" });
    const strong = signals.filter((s) => s.weight === "strong").length;
    decided.push(`Message on its own: ${signals.length ? `${plural(signals.length, "warning sign")} (${strong} strong)` : "no warning signs"}, rated ${LABEL[alone.level]} by the message rules.`);
  }

  for (const slug of linkedSlugs) {
    const r = repos.get(slug);
    if (!r) { links.push({ slug, state: "not-scanned", effect: "Not scanned yet, so it has no effect on the level." }); continue; }
    if ("failed" in r) { links.push({ slug, state: "failed", effect: "The scan failed, so it has no effect on the level. A failed scan is not a safety result." }); continue; }
    const { scan } = r;
    for (const f of scan.findings) if (f.severity !== "low") evidence.push({ from: "repository", repo: slug, title: `[${f.severity}] ${f.title}`, where: `${f.file}:${f.line}`, strong: IMPORTANT.includes(f.severity) });
    const counts = `${scan.counts.critical} critical, ${scan.counts.high} high, ${scan.counts.medium} medium`;
    if (scan.verdict === "do-not-run" && scan.complete) {
      links.push({ slug, state: "do-not-run", effect: `Full scan rated it "Do not run" (${counts}). This raises the message to high concern.` });
    } else if (scan.verdict === "do-not-run" || scan.verdict === "review-first") {
      const raised = RANK[level] < RANK["worth-checking"];
      if (raised) level = "worth-checking";
      const what = scan.verdict === "do-not-run" ? `"Do not run" findings in a partial scan` : `findings to review (${counts})`;
      links.push({ slug, state: scan.verdict === "do-not-run" ? "incomplete" : "review-first", effect: `It has ${what}.${raised ? " This raises the level to worth checking." : ""}${scan.complete ? "" : " The scan was incomplete, so it cannot raise the level to high."}` });
    } else if (scan.verdict === "incomplete") {
      links.push({ slug, state: "incomplete", effect: `${plural(scan.issues.length, "item")} could not be inspected. An incomplete scan has no effect on the level and is not a clean result.` });
    } else {
      links.push({ slug, state: "no-known-indicators", effect: "No known indicators in this scan. This never lowers the level, and it is not proof of safety." });
    }
  }
  for (const l of links) decided.push(`Linked repository ${l.slug}: ${l.effect}`);

  const unlinked = [...repos.keys()].filter((s) => !linkedSlugs.includes(s));
  if (!message) {
    // Repository only: the level follows the scan verdict and no message evidence exists.
    for (const s of unlinked) {
      const r = repos.get(s)!;
      if (!("scan" in r)) continue;
      for (const f of r.scan.findings) if (f.severity !== "low") evidence.push({ from: "repository", repo: s, title: `[${f.severity}] ${f.title}`, where: `${f.file}:${f.line}`, strong: IMPORTANT.includes(f.severity) });
      const own: ConcernLevel = r.scan.verdict === "do-not-run" && r.scan.complete ? "high" : r.scan.verdict === "do-not-run" || r.scan.verdict === "review-first" ? "worth-checking" : "low";
      if (RANK[own] > RANK[level]) level = own;
      decided.push(`Repository ${s} (no message scanned): rated ${LABEL[own]} from its scan alone.`);
    }
  } else if (unlinked.length) {
    decided.push(`Not linked from this message, so not counted: ${unlinked.join(", ")}.`);
  }
  if (message && !linkedSlugs.length) decided.push("The message links to no GitHub repository, so the level comes from the message alone.");
  decided.push(`Final level: ${LABEL[level]}. Decoy never rates anything safe; low concern means no known warning signs were found.`);

  // Next steps, most important first, each drawn from evidence above.
  const relevant = message ? linkedSlugs : unlinked;
  for (const slug of relevant) {
    const r = repos.get(slug);
    if (!r) { actions.push(`Scan ${slug} before running anything from it. Decoy reads it from GitHub and never runs it.`); continue; }
    if ("failed" in r) { actions.push(`Retry the scan of ${slug}, or read its package.json scripts yourself before running anything.`); continue; }
    const { scan } = r;
    const files = keyFiles(scan);
    if (scan.verdict === "do-not-run") actions.push(`Do not run, install or build ${slug}, and don't open it in an editor that runs tasks automatically.`);
    if (files.length) actions.push(`Review ${files.join(", ")} in ${slug}. These hold the critical and high findings.`);
    if (scan.verdict === "review-first" && !files.length) actions.push(`Review the medium findings in ${slug} before running anything.`);
    if (!scan.complete) actions.push(`Treat ${slug} as unchecked where ${plural(scan.issues.length, "item")} could not be inspected.`);
    if (scan.verdict === "do-not-run" || scan.verdict === "review-first") actions.push(`Verify the repository owner: is github.com/${owner(slug)} really who the sender claims to be?`);
    if (scan.verdict === "no-known-indicators") actions.push(`Before installing ${slug}, still read its package.json scripts and setup instructions.`);
  }
  if (input.seedPhrase) actions.unshift("Move any funds from a wallet whose recovery phrase was shared, and never type it anywhere.");
  if (signals.some((s) => s.id === "suspicious-command" || s.id === "paste-command" || s.weight === "strong")) actions.push("Don't paste or run commands from the message. Check the request through a channel you already trust.");
  if (assessment && !actions.length) actions.push(level === "low" ? "No action suggested by the rules. If anything feels off, check with the sender through a channel you already trust." : "Check the request with the sender through a channel you already trust before acting.");

  return { level, messageLevel: alone?.level, links, unlinked, evidence, decided, actions: [...new Set(actions)] };
}
