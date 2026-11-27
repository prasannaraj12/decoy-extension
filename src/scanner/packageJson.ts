import { COMMON_HOOK_COMMANDS, IMPLICIT_HOOKS, INSTALL_HOOKS, type Category, type Confidence, type Severity } from "./rules";
import { classifyUrl } from "./url";

export interface PkgFinding { ruleId: string; title: string; category: Category; severity: Severity; confidence: Confidence; line: number; evidence: string; explanation: string; remediation: string; }

/** Removes comments and trailing commas outside strings (accepted by some package managers and editors). */
export function parseLenient(text: string): { value: any; lenient: boolean } | null {
  try { return { value: JSON.parse(text), lenient: false }; } catch { /* try again below */ }
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { // copy the string verbatim
      const start = i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      out += text.slice(start, i + 1);
    } else if (c === "/" && text[i + 1] === "/") { while (i + 1 < text.length && text[i + 1] !== "\n") i++; }
    else if (c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); i = e < 0 ? text.length : e + 1; }
    else if (c === ",") { const next = text.slice(i + 1).match(/^(?:\s|\/\/[^\n]*|\/\*[\s\S]*?\*\/)*([\s\S])/)?.[1]; if (next !== "}" && next !== "]") out += c; }
    else out += c;
  }
  try { return { value: JSON.parse(out), lenient: true }; } catch { return null; }
}

function dependencySource(spec: string): Pick<PkgFinding, "ruleId" | "title" | "severity" | "confidence" | "explanation"> | null {
  if (/^(git\+|git:|ssh:|github:|gitlab:|bitbucket:|gist:)|^git@|\.git(#|$)/i.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec)) {
    return { ruleId: "dependency-git", title: "Dependency installed from a git repository", severity: "medium", confidence: "medium", explanation: "Bypasses the npm registry, can change at any time, and runs its own prepare script on install." };
  }
  if (/^https?:/i.test(spec)) {
    if (classifyUrl(spec) === "allowed") return null;
    return { ruleId: "dependency-url", title: "Dependency downloaded from a URL", severity: "high", confidence: "high", explanation: "Installs an archive from a server outside the npm registry, so it can run any install script." };
  }
  if (/^(file|link|portal):/i.test(spec) && /\.(tgz|tar|gz)$/i.test(spec)) {
    return { ruleId: "dependency-local-archive", title: "Dependency installed from a bundled archive", severity: "medium", confidence: "medium", explanation: "The archive's contents are not inspected by this scan." };
  }
  if (/^npm:/i.test(spec)) {
    return { ruleId: "dependency-alias", title: "Dependency is an alias for another package", severity: "low", confidence: "low", explanation: "The name imported in code is not the package that gets installed." };
  }
  return null;
}

export function scanPackageJson(content: string): { findings: PkgFinding[]; parseError: boolean } {
  const lines = content.split(/\r\n|[\n\r\u2028\u2029]/);
  const out: PkgFinding[] = [];
  /** Line of `"key":` at or after the line that opens `section`; falls back to the section itself. */
  const lineOf = (section: string, key: string) => {
    const at = (k: string, from: number) => lines.findIndex((l, i) => i >= from && l.includes(JSON.stringify(k)) && /:/.test(l));
    const s = Math.max(0, at(section, 0));
    const k = at(key, s);
    return (k < 0 ? s : k) + 1;
  };
  const hook = (name: string, cmd: string, line: number) => {
    const install = INSTALL_HOOKS.includes(name);
    const common = COMMON_HOOK_COMMANDS.test(cmd.trim());
    out.push({
      ruleId: install ? "npm-lifecycle-script" : "npm-implicit-script",
      title: install ? `Runs code automatically on npm install ("${name}")` : `Runs code automatically around another command ("${name}")`,
      category: "Automatic execution", severity: common ? "low" : install ? "high" : "medium", confidence: common ? "low" : "high",
      line, evidence: `"${name}": "${cmd}"`,
      explanation: install ? "This script executes as soon as you run `npm install`, before you've had a chance to read the project."
        : "This script runs without being named when you use the matching npm command, or when the package is packed.",
      remediation: "Install with `npm install --ignore-scripts` and read the script first.",
    });
  };

  const parsed = parseLenient(content);
  if (!parsed || typeof parsed.value !== "object" || !parsed.value) {
    // Unparseable: still report anything that looks like a hook, and let the caller mark the scan incomplete.
    lines.forEach((l, i) => {
      for (const m of l.matchAll(/["']?(\w+)["']?\s*:\s*["']([^"'\n]+)["']/g)) if (INSTALL_HOOKS.includes(m[1])) hook(m[1], m[2], i + 1);
    });
    return { findings: out, parseError: true };
  }
  const pkg = parsed.value;
  if (parsed.lenient) out.push({
    ruleId: "malformed-package-json", title: "package.json is not valid JSON", category: "Automatic execution", severity: "low", confidence: "high", line: 1, evidence: lines[0] || "package.json",
    explanation: "It contains comments or trailing commas. Some tools accept this and others don't, which can hide scripts from scanners.", remediation: "Review the scripts section by hand.",
  });
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  for (const name of [...INSTALL_HOOKS, ...IMPLICIT_HOOKS]) if (typeof scripts[name] === "string") hook(name, scripts[name], lineOf("scripts", name));

  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"]) {
    const deps = pkg[section];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) {
      const hit = typeof spec === "string" ? dependencySource(spec.trim()) : null;
      if (hit) out.push({ ...hit, category: "Dependency source", line: lineOf(section, name), evidence: `"${name}": "${spec}"`, remediation: "Check the source before installing, and use `npm install --ignore-scripts`." });
    }
  }
  return { findings: out, parseError: false };
}
