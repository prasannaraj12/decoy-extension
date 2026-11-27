// Risky Change Detector: a local snapshot of each completed repository scan, compared with the next scan of the same
// repository. Snapshots stay in chrome.storage.local and hold no source code: evidence is kept only as a SHA-256 hash.
import type { Finding, ScanResult } from "./scanner/scan";
import type { Severity } from "./scanner/rules";
import type { DependencyMap } from "./deps";

export const SNAPSHOT_VERSION = 1;
export const MAX_SNAPSHOTS = 50;
/** Snapshots older than this are still compared, but flagged as old. */
export const STALE_DAYS = 90;
const KEY = "decoy.snapshots.v1";

export interface SnapshotFinding { ruleId: string; title: string; severity: Severity; file: string; line: number; fp: string; }
export interface Snapshot {
  v: number; slug: string; commit?: string; scannedAt: number; complete: boolean; verdict: string;
  counts: Record<Severity, number>; files: string[]; findings: SnapshotFinding[]; deps: string[];
}

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** Identity of a finding that survives the code moving to another line. */
const fingerprint = (f: Finding) => sha256(`${f.ruleId}\u0000${f.file}\u0000${f.evidence.replace(/\s+/g, " ").trim()}`);

export async function makeSnapshot(slug: string, scan: ScanResult, files: string[], deps: DependencyMap | undefined, opts: { commit?: string; now?: number } = {}): Promise<Snapshot> {
  return {
    v: SNAPSHOT_VERSION, slug, commit: opts.commit, scannedAt: opts.now ?? Date.now(), complete: scan.complete, verdict: scan.verdict,
    counts: { ...scan.counts }, files: [...files].sort(),
    findings: await Promise.all(scan.findings.map(async (f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, file: f.file, line: f.line, fp: await fingerprint(f) }))),
    deps: deps ? deps.deps.map((d) => `${d.manifest}#${d.name}@${d.spec}`).sort() : [],
  };
}

/** Accepts only a well-formed snapshot of this version; anything else is treated as missing. */
export function validSnapshot(x: any): x is Snapshot {
  return !!x && x.v === SNAPSHOT_VERSION && typeof x.slug === "string" && typeof x.scannedAt === "number" && Array.isArray(x.findings) && Array.isArray(x.files) && Array.isArray(x.deps)
    && x.findings.every((f: any) => f && typeof f.ruleId === "string" && typeof f.file === "string" && typeof f.fp === "string" && typeof f.severity === "string");
}

export interface ChangedFinding { before: SnapshotFinding; after: SnapshotFinding; what: string[]; }
export interface ScanDiff {
  previousAt: number; currentAt: number; previousCommit?: string; currentCommit?: string;
  sameCommit: boolean; stale: boolean;
  added: SnapshotFinding[]; resolved: SnapshotFinding[]; notRechecked: SnapshotFinding[]; changed: ChangedFinding[];
  /** Files that are new since the previous scan and now have a medium-or-higher finding. */
  newRiskyFiles: string[];
  addedDeps: string[]; removedDeps: string[];
  notes: string[];
}

const SEV: Severity[] = ["critical", "high", "medium", "low"];
const risky = (f: SnapshotFinding) => f.severity !== "low";

export function diffSnapshots(prev: Snapshot, cur: Snapshot, uninspected: ReadonlySet<string> = new Set()): ScanDiff {
  const key = (f: SnapshotFinding) => f.fp;
  const before = new Map(prev.findings.map((f) => [key(f), f]));
  const after = new Map(cur.findings.map((f) => [key(f), f]));
  const added: SnapshotFinding[] = [], resolved: SnapshotFinding[] = [], notRechecked: SnapshotFinding[] = [], changed: ChangedFinding[] = [];
  for (const [k, f] of after) {
    const b = before.get(k);
    if (!b) { added.push(f); continue; }
    const what: string[] = [];
    if (b.severity !== f.severity) what.push(`severity ${b.severity} → ${f.severity}`);
    if (b.line !== f.line) what.push(`line ${b.line} → ${f.line}`);
    if (what.length) changed.push({ before: b, after: f, what });
  }
  const curFiles = new Set(cur.files);
  for (const [k, f] of before) {
    if (after.has(k)) continue;
    // Gone from the results only counts as resolved if the file was inspected this time (or no longer exists in a complete scan).
    if (uninspected.has(f.file) || (!cur.complete && !curFiles.has(f.file))) notRechecked.push(f); else resolved.push(f);
  }
  const prevFiles = new Set(prev.files);
  const newRiskyFiles = [...new Set(added.filter((f) => risky(f) && !prevFiles.has(f.file)).map((f) => f.file))].sort();
  const pd = new Set(prev.deps), cd = new Set(cur.deps);
  const notes: string[] = [];
  const sameCommit = !!prev.commit && prev.commit === cur.commit;
  const stale = cur.scannedAt - prev.scannedAt > STALE_DAYS * 864e5;
  if (sameCommit) notes.push("Same commit as the previous scan. Any differences come from changes to Decoy's rules, not to the repository.");
  if (stale) notes.push(`The previous snapshot is more than ${STALE_DAYS} days old, so many changes may be grouped together.`);
  if (!prev.complete) notes.push("The previous scan was incomplete, so some findings marked new may have existed before.");
  if (!cur.complete) notes.push("This scan is incomplete. Findings in files that were not inspected are listed as not rechecked, not resolved.");
  const order = (a: SnapshotFinding, b: SnapshotFinding) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line;
  return {
    previousAt: prev.scannedAt, currentAt: cur.scannedAt, previousCommit: prev.commit, currentCommit: cur.commit, sameCommit, stale,
    added: added.sort(order), resolved: resolved.sort(order), notRechecked: notRechecked.sort(order), changed,
    newRiskyFiles, addedDeps: [...cd].filter((d) => !pd.has(d)), removedDeps: [...pd].filter((d) => !cd.has(d)), notes,
  };
}

/** Minimal storage surface, so tests can supply a fake and failures can be simulated. */
export interface SnapshotStorage { get(key: string): Promise<Record<string, any>>; set(items: Record<string, any>): Promise<void>; }
export const chromeLocal = (): SnapshotStorage => chrome.storage.local;

export type LoadResult = { state: "found"; snapshot: Snapshot } | { state: "none" } | { state: "unreadable" } | { state: "error"; message: string };

export async function loadSnapshot(store: SnapshotStorage, slug: string): Promise<LoadResult> {
  try {
    const all = (await store.get(KEY))[KEY];
    const s = all && typeof all === "object" ? all[slug] : undefined;
    if (s === undefined) return { state: "none" };
    return validSnapshot(s) ? { state: "found", snapshot: s } : { state: "unreadable" };
  } catch (e: any) { return { state: "error", message: String(e?.message ?? e) }; }
}

/** Saves one snapshot per repository and keeps the most recent MAX_SNAPSHOTS. */
export async function saveSnapshot(store: SnapshotStorage, s: Snapshot): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const raw = (await store.get(KEY))[KEY];
    const all: Record<string, Snapshot> = {};
    if (raw && typeof raw === "object") for (const [k, v] of Object.entries(raw)) if (validSnapshot(v)) all[k] = v;
    all[s.slug] = s;
    const kept = Object.fromEntries(Object.entries(all).sort((a, b) => b[1].scannedAt - a[1].scannedAt).slice(0, MAX_SNAPSHOTS));
    await store.set({ [KEY]: kept });
    return { ok: true };
  } catch (e: any) { return { ok: false, message: String(e?.message ?? e) }; }
}
