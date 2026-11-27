// Dependency Risk Map: the direct dependencies declared in each package.json, joined to the findings the scanner
// already produced. Nothing here is guessed: transitive dependencies and package contents are not analysed.
import type { Finding } from "./scanner/scan";
import { parseLenient } from "./scanner/packageJson";
import { isPackageJson, isLockfile } from "./scanner/files";

export const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"] as const;

/**
 * flagged: the scanner has a finding for this dependency's declared source.
 * source-checked: its declared source was checked and nothing was found; the package's own code was not analysed.
 * not-analysed: the entry could not be checked (for example, an object instead of a version string).
 */
export type DepStatus = "flagged" | "source-checked" | "not-analysed";
export interface Dependency { manifest: string; section: string; name: string; spec: string; status: DepStatus; findings: Finding[]; }
export interface Manifest { path: string; state: "parsed" | "unparseable"; name?: string; count: number; }
export interface DependencyMap {
  manifests: Manifest[];
  deps: Dependency[];
  /** Lockfile findings: a resolved URL outside the registry. Not attributed to a package, because the lockfile isn't parsed into a tree. */
  lockfileFindings: Finding[];
  lockfiles: string[];
}

const evidenceFor = (name: string, spec: string) => `"${name}": "${spec}"`;

export function buildDependencyMap(files: { path: string; content: string }[], findings: Finding[]): DependencyMap {
  const manifests: Manifest[] = [];
  const deps: Dependency[] = [];
  for (const f of files.filter((x) => isPackageJson(x.path)).sort((a, b) => a.path.localeCompare(b.path))) {
    const parsed = parseLenient(f.content.replace(/^﻿/, ""));
    if (!parsed || typeof parsed.value !== "object" || !parsed.value) { manifests.push({ path: f.path, state: "unparseable", count: 0 }); continue; }
    const pkg = parsed.value;
    let count = 0;
    for (const section of SECTIONS) {
      const entries = pkg[section];
      if (!entries || typeof entries !== "object") continue;
      for (const [name, spec] of Object.entries(entries)) {
        count++;
        if (typeof spec !== "string") { deps.push({ manifest: f.path, section, name, spec: "(not a version string)", status: "not-analysed", findings: [] }); continue; }
        const ev = evidenceFor(name, spec);
        const hits = findings.filter((x) => x.file === f.path && x.category === "Dependency source" && x.evidence.startsWith(ev.slice(0, 150)));
        deps.push({ manifest: f.path, section, name, spec, status: hits.length ? "flagged" : "source-checked", findings: hits });
      }
    }
    manifests.push({ path: f.path, state: "parsed", name: typeof pkg.name === "string" ? pkg.name : undefined, count });
  }
  return {
    manifests, deps,
    lockfileFindings: findings.filter((x) => x.ruleId === "lockfile-untrusted-source"),
    lockfiles: files.filter((x) => isLockfile(x.path)).map((x) => x.path).sort(),
  };
}

const RANK = { flagged: 0, "not-analysed": 1, "source-checked": 2 } as const;
/** Flagged first, then by name: what the map shows before "show more". */
export const sortDeps = (d: Dependency[]) => [...d].sort((a, b) => RANK[a.status] - RANK[b.status] || a.name.localeCompare(b.name));
