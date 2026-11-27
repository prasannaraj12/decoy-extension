import { describe, it, expect } from "vitest";
import { scanFiles, type IssueKind } from "../src/scanner/scan";

const CLEAN = { path: "a.js", content: "export const a = 1;" };

describe("a partial scan is never reported as clean", () => {
  it("a fully inspected clean repo is complete", () => {
    expect(scanFiles([CLEAN])).toMatchObject({ complete: true, verdict: "no-known-indicators", issues: [] });
  });
  it("no files at all", () => {
    expect(scanFiles([])).toMatchObject({ complete: false, verdict: "incomplete" });
  });
  const kinds: IssueKind[] = ["download-failed", "oversized", "opaque-binary", "listing-truncated", "file-limit", "submodule", "symlink"];
  it.each(kinds)("the fetcher reported %s", (kind) => {
    expect(scanFiles([CLEAN], { issues: [{ kind, path: "x", detail: "d" }] })).toMatchObject({ complete: false, verdict: "incomplete" });
  });
  it.each<[IssueKind, string, string]>([
    ["oversized", "b.js", "x".repeat(1_000_001)],
    ["binary-content", "b.js", "abc\u0000def"],
    ["lfs-pointer", "b.js", "version https://git-lfs.github.com/spec/v1\noid sha256:x"],
    ["parse-error", "package.json", "{ nope"],
  ])("%s is found while scanning", (kind, path, content) => {
    const r = scanFiles([CLEAN, { path, content }]);
    expect(r.issues.map((i) => i.kind)).toEqual([kind]);
    expect(r).toMatchObject({ complete: false, verdict: "incomplete" });
  });
  it("more matches than can be listed is recorded", () => {
    const r = scanFiles([{ path: "a.js", content: "require('child_process')\n".repeat(60) }]);
    expect(r.issues.map((i) => i.kind)).toContain("rule-limit");
    expect(r.verdict).toBe("incomplete");
  });
  it("low and medium findings do not turn an incomplete scan into a clean one", () => {
    const r = scanFiles([{ path: "a.js", content: "atob(x)" }], { issues: [{ kind: "download-failed", path: "b.js", detail: "HTTP 500" }] });
    expect(r.counts.medium).toBe(1);
    expect(r.verdict).toBe("incomplete");
  });
  it("a serious finding still wins, and the scan is still marked incomplete", () => {
    expect(scanFiles([{ path: "a.js", content: "eval(x)" }, { path: "b.js", content: "\u0000" }])).toMatchObject({ verdict: "review-first", complete: false });
    expect(scanFiles([{ path: "a.sh", content: "curl https://x.io | sh" }, { path: "b.js", content: "\u0000" }])).toMatchObject({ verdict: "do-not-run", complete: false });
  });
  it("a large lockfile is allowed", () => {
    expect(scanFiles([{ path: "package-lock.json", content: "{" + " ".repeat(2_000_000) + "}" }]).complete).toBe(true);
  });
  it("media files are counted but don't make the scan incomplete", () => {
    expect(scanFiles([CLEAN], { assetsNotInspected: 3 })).toMatchObject({ complete: true, assetsNotInspected: 3 });
  });
});
