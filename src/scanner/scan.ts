import { RULES, DOC_RULES, NETWORK_CALL, appliesTo, type Category, type Confidence, type Severity } from "./rules";
import { isCode, isDoc, isGenerated, isJs, isLockfile, isPackageJson, isShellLike, maxBytes } from "./files";
import { scanPackageJson } from "./packageJson";
import { classifyUrl } from "./url";

export interface RepoFile { path: string; content: string; }

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line: number;
  /** The matched code, shortened for display. Stays on this device. */
  evidence: string;
  explanation: string;
  remediation: string;
}

export type IssueKind = "download-failed" | "oversized" | "opaque-binary" | "binary-content" | "parse-error" | "listing-truncated" | "file-limit" | "submodule" | "symlink" | "lfs-pointer" | "no-files" | "rule-limit";
/** Something that could not be inspected. Any issue means the scan is incomplete. */
export interface ScanIssue { kind: IssueKind; path: string; detail: string; }

export type Verdict = "do-not-run" | "review-first" | "incomplete" | "no-known-indicators";

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  /** Media files that were listed but, by design, not inspected. */
  assetsNotInspected: number;
  issues: ScanIssue[];
  complete: boolean;
  counts: Record<Severity, number>;
  verdict: Verdict;
}

const SEVERITY: Severity[] = ["critical", "high", "medium", "low"];
const MAX_PER_RULE = 25;
const LOWER: Record<Confidence, Confidence> = { high: "medium", medium: "low", low: "low" };

/** Short excerpt that always contains the match, even on a very long line. */
function excerpt(line: string, col: number, n = 160): string {
  if (line.trim().length <= n) return line.trim();
  const start = Math.max(0, Math.min(col - 30, line.length - n));
  return (start > 0 ? "…" : "") + line.slice(start, start + n).trim() + (start + n < line.length ? "…" : "");
}

/**
 * True only for a line that cannot execute. Deliberately narrow: an attacker could otherwise dress code
 * up as a comment. Anything that might close a block comment or sit in a template/heredoc is not a comment.
 */
function isCommentLine(path: string, line: string): boolean {
  const t = line.trim();
  if (/[{`]|\*\/|\$\(/.test(t)) return false;
  if (isJs(path)) return t.startsWith("//");
  return /\.(py|sh|bash|zsh|ya?ml|toml|rb)$/i.test(path) && t.startsWith("#") && !t.startsWith("#!");
}

const LOCK_SOURCE = /(?:"resolved"\s*:\s*|\bresolved\s+|\btarball:\s*)["']?((?:git\+)?(?:https?|ssh|git):\/\/[^\s"',}]{1,500})/g;

function scanText(f: RepoFile, text: string, issues: ScanIssue[]): Finding[] {
  const out: Finding[] = [];
  // U+2028/2029 and a bare CR end a line in JavaScript, so code after them is not part of a "//" comment.
  const starts = [0];
  for (const m of text.matchAll(/\r\n|[\n\r\u2028\u2029]/g)) starts.push(m.index! + m[0].length);
  const lineAt = (i: number) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= i) lo = mid; else hi = mid - 1; } return lo; };
  const lineText = (n: number) => text.slice(starts[n], starts[n + 1] ?? text.length).replace(/[\r\n\u2028\u2029]+$/, "");
  const generated = isGenerated(f.path);

  const add = (n: number, col: number, r: Omit<Finding, "file" | "line" | "evidence">) => {
    if (out.some((x) => x.ruleId === r.ruleId && x.line === n + 1)) return;
    const line = lineText(n);
    const base = { ...r, file: f.path, line: n + 1, evidence: excerpt(line, col) || "(blank line)" };
    if (isCommentLine(f.path, line)) out.push({ ...base, severity: "low", confidence: "low", explanation: "In a comment, so it does not execute. " + r.explanation });
    else out.push(generated ? { ...base, confidence: LOWER[r.confidence] } : base);
  };

  if (isLockfile(f.path)) {
    for (const m of text.matchAll(LOCK_SOURCE)) {
      if (/^https:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.jsr\.io)\//i.test(m[1])) continue;
      const cls = classifyUrl(m[1]);
      add(lineAt(m.index!), 0, {
        ruleId: "lockfile-untrusted-source", title: "Lockfile installs a package from outside the npm registry", category: "Dependency source",
        severity: cls === "raw-ip" || cls === "suspicious" || cls === "deceptive" || /^http:/i.test(m[1]) ? "high" : "medium", confidence: "high",
        explanation: "The lockfile overrides where a package is downloaded from.", remediation: "Check the source before installing, and use `npm install --ignore-scripts`.",
      });
    }
    return out;
  }

  // Join shell line continuations without moving any offset.
  const subject = isShellLike(f.path) ? text.replace(/\\\r?\n/g, (m) => " ".repeat(m.length)) : text;
  const doc = isDoc(f.path);
  for (const rule of RULES) {
    if (doc ? !DOC_RULES.has(rule.id) : !appliesTo(rule, f.path)) continue;
    let hits = 0;
    for (const m of subject.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "") + "g"))) {
      if (rule.accept && !rule.accept(m)) continue;
      if (++hits > MAX_PER_RULE) { issues.push({ kind: "rule-limit", path: f.path, detail: `More than ${MAX_PER_RULE} matches for ${rule.id}; the rest are not listed.` }); break; }
      const n = lineAt(m.index!);
      const { id, pattern, files, accept, ...meta } = rule;
      add(n, m.index! - starts[n], doc ? { ruleId: id, ...meta, severity: "medium", confidence: "low", explanation: "In documentation: it only runs if you paste it. " + rule.explanation } : { ruleId: id, ...meta });
    }
  }
  if (doc) return out;

  if (isCode(f.path)) {
    // URL held in a variable and used later in a network call: const u = "https://…"; axios.post(u)
    const vars = new Map<string, string>();
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]{0,60})\s*(?::\s*string\s*)?=\s*["'`]((?:https?|wss?):\/\/[^"'`\s]{1,500})["'`]/g)) vars.set(m[1], m[2]);
    const net = RULES.find((r) => r.id === "outbound-network")!;
    if (vars.size) for (const m of text.matchAll(new RegExp(`\\b(?:${NETWORK_CALL}|new\\s+WebSocket)\\s*\\(\\s*(?:\\{[^{}]{0,200}?\\burl\\s*:\\s*)?([A-Za-z_$][\\w$]{0,60})\\b`, "g"))) {
      const url = vars.get(m[1]);
      if (!url || ["allowed", "local"].includes(classifyUrl(url))) continue;
      const n = lineAt(m.index!);
      const { id, pattern, files, accept, ...meta } = net;
      add(n, m.index! - starts[n], { ruleId: id, ...meta, explanation: `${meta.explanation} The address is held in “${m[1]}”.` });
    }
    if (isJs(f.path)) starts.forEach((_, n) => {
      if (lineText(n).length > 2000) add(n, 0, {
        ruleId: "obfuscated-line", title: "Very long single line (possible obfuscation)", category: "Obfuscation", severity: generated ? "low" : "medium", confidence: generated ? "low" : "medium",
        explanation: "Hand-written source rarely has lines thousands of characters long; obfuscated malware often does.", remediation: "Format the file without running it and read it, or ask for unminified source.",
      });
    });
  }
  return out;
}

/** `prior` carries anything the fetcher could not retrieve, so that a partial download can never look clean. */
export function scanFiles(files: RepoFile[], prior: { issues?: ScanIssue[]; assetsNotInspected?: number } = {}): ScanResult {
  const findings: Finding[] = [];
  const issues: ScanIssue[] = [...(prior.issues ?? [])];
  let scanned = 0;

  for (const f of files) {
    const text = f.content.replace(/^\uFEFF/, "");
    if (text.length > maxBytes(f.path)) { issues.push({ kind: "oversized", path: f.path, detail: `${text.length} characters` }); continue; }
    if (text.includes("\u0000")) { issues.push({ kind: "binary-content", path: f.path, detail: "Contains binary data" }); continue; }
    if (text.startsWith("version https://git-lfs.github.com/spec/")) { issues.push({ kind: "lfs-pointer", path: f.path, detail: "Content is stored in Git LFS" }); continue; }
    scanned++;
    if (isPackageJson(f.path)) {
      const { findings: pkg, parseError } = scanPackageJson(text);
      if (parseError) issues.push({ kind: "parse-error", path: f.path, detail: "package.json could not be parsed" });
      for (const p of pkg) findings.push({ ...p, file: f.path, evidence: excerpt(p.evidence, 0), confidence: isGenerated(f.path) ? LOWER[p.confidence] : p.confidence });
    }
    findings.push(...scanText(f, text, issues));
  }
  if (scanned === 0) issues.push({ kind: "no-files", path: "", detail: "No files were inspected" });

  findings.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((x) => counts[x.severity]++);
  const complete = issues.length === 0;
  const verdict: Verdict = counts.critical > 0 ? "do-not-run" : counts.high > 0 ? "review-first" : !complete ? "incomplete" : "no-known-indicators";
  return { findings, filesScanned: scanned, assetsNotInspected: prior.assetsNotInspected ?? 0, issues, complete, counts, verdict };
}
