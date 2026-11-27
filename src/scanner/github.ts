import type { RepoFile, ScanIssue } from "./scan";
import { isAsset, isOpaque, maxBytes, priority } from "./files";

// Fetches a public repo's text files WITHOUT cloning or executing anything.
// Uses 2 GitHub API calls (unauthenticated limit: 60/hour) + raw file downloads, all pinned to one commit.

const MAX_FILES = 600;
const MAX_TOTAL_BYTES = 30_000_000;
const CONCURRENCY = 8;

export interface RepoRef { owner: string; repo: string; /** May be "branch", "branch/with/slash" or "branch/sub/path": GitHub URLs are ambiguous. */ ref?: string; }

export function parseRepoUrl(input: string): RepoRef | null {
  const s = input.trim().replace(/[.,;:!?)\]}>'"]+$/, "");
  const ssh = s.match(/^(?:ssh:\/\/)?git@github\.com[:/](.+)$/i);
  let path: string;
  if (ssh) path = ssh[1];
  else {
    let u: URL;
    try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s); } catch { return null; }
    // Exact host and no userinfo: "github.com.evil.xyz", "evil.com/github.com/a/b" and "github.com@evil.com" are not GitHub.
    if (!/^https?:$/.test(u.protocol) || !/^(www\.)?github\.com$/i.test(u.hostname) || u.username || u.password) return null;
    path = u.pathname;
  }
  const [owner, rawRepo, kind, ...rest] = path.split("/").filter(Boolean);
  const repo = rawRepo?.replace(/\.git$/i, "");
  if (!owner || !repo || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo) || /^\.+$/.test(repo)) return null;
  let ref: string | undefined;
  if (rest.length && /^(tree|blob|commit|commits)$/.test(kind ?? "")) { try { ref = decodeURIComponent(rest.join("/")); } catch { return null; } }
  return { owner, repo, ref };
}

async function apiError(r: Response, what: string): Promise<Error> {
  if (r.status === 403 || r.status === 429) return new Error(`GitHub rate limit reached or access denied (${r.status}) while reading ${what}. The repository was not scanned.`);
  if (r.status === 404 || r.status === 422) return new Error(`${what} not found, or the repository is private (${r.status}).`);
  return new Error(`GitHub returned ${r.status} for ${what}. The repository was not scanned.`);
}

/** Resolves to a commit SHA, trying shorter prefixes when the URL may include a sub-path. */
async function resolveCommit(api: string, ref: string | undefined): Promise<string> {
  const parts = (ref ?? "HEAD").split("/");
  let last: Response | undefined;
  for (let n = parts.length; n > 0 && parts.length - n < 5; n--) {
    last = await fetch(`${api}/commits/${encodeURIComponent(parts.slice(0, n).join("/"))}`);
    if (last.ok) {
      const { sha } = await last.json();
      if (/^[0-9a-f]{40}$/.test(sha ?? "")) return sha;
      throw new Error("GitHub returned an unexpected commit response. The repository was not scanned.");
    }
    if (last.status !== 404 && last.status !== 422) break;
  }
  throw await apiError(last!, ref ? `Branch or commit "${ref}"` : "Repository");
}

function decode(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  const enc = b[0] === 0xff && b[1] === 0xfe ? "utf-16le" : b[0] === 0xfe && b[1] === 0xff ? "utf-16be" : "utf-8"; // PowerShell often writes UTF-16
  return new TextDecoder(enc).decode(buf);
}

export interface FetchedRepo { files: RepoFile[]; issues: ScanIssue[]; assetsNotInspected: number; slug: string; commit: string; }

export async function fetchRepo(url: string, onProgress?: (done: number, total: number) => void): Promise<FetchedRepo> {
  const p = parseRepoUrl(url);
  if (!p) throw new Error("Not a GitHub repository URL");
  const api = `https://api.github.com/repos/${p.owner}/${p.repo}`;
  const commit = await resolveCommit(api, p.ref);
  const treeRes = await fetch(`${api}/git/trees/${commit}?recursive=1`);
  if (!treeRes.ok) throw await apiError(treeRes, "File listing");
  const tree = await treeRes.json();
  if (!Array.isArray(tree.tree)) throw new Error("GitHub returned an unexpected file listing. The repository was not scanned.");

  const issues: ScanIssue[] = [];
  if (tree.truncated) issues.push({ kind: "listing-truncated", path: "", detail: "GitHub did not return the full file list" });

  let assetsNotInspected = 0;
  const wanted: { path: string; size: number }[] = [];
  for (const t of tree.tree) {
    if (t.type === "commit") issues.push({ kind: "submodule", path: t.path, detail: "Git submodule (a separate repository) was not inspected" });
    if (t.type !== "blob") continue;
    if (t.mode === "120000") issues.push({ kind: "symlink", path: t.path, detail: "Symbolic link was not followed" });
    else if (isAsset(t.path)) assetsNotInspected++;
    else if (isOpaque(t.path)) issues.push({ kind: "opaque-binary", path: t.path, detail: "Binary or archive cannot be inspected" });
    else if ((t.size ?? 0) > maxBytes(t.path)) issues.push({ kind: "oversized", path: t.path, detail: `${t.size} bytes` });
    else wanted.push({ path: t.path, size: t.size ?? 0 });
  }
  wanted.sort((a, b) => priority(a.path) - priority(b.path));

  const pick: typeof wanted = [];
  let bytes = 0, dropped = 0;
  for (const w of wanted) {
    if (pick.length >= MAX_FILES || bytes + w.size > MAX_TOTAL_BYTES) { dropped++; continue; }
    bytes += w.size;
    pick.push(w);
  }
  if (dropped) issues.push({ kind: "file-limit", path: "", detail: `${dropped} file(s) beyond the scan limit were not inspected` });

  const files: RepoFile[] = [];
  let done = 0, next = 0;
  const worker = async () => {
    while (next < pick.length) {
      const { path } = pick[next++];
      try {
        const r = await fetch(`https://raw.githubusercontent.com/${p.owner}/${p.repo}/${commit}/${path.split("/").map(encodeURIComponent).join("/")}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        files.push({ path, content: decode(await r.arrayBuffer()) });
      } catch (e: any) {
        issues.push({ kind: "download-failed", path, detail: e?.message ?? String(e) });
      }
      onProgress?.(++done, pick.length);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return { files, issues, assetsNotInspected, slug: `${p.owner}/${p.repo}`.toLowerCase(), commit };
}
