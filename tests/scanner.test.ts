import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanFiles } from "../src/scanner/scan";
import { scanMessage, extractLinks } from "../src/scanner/message";
import { redact } from "../src/redact";
import { cloudPayload } from "../src/ai/prompts";

const root = join(__dirname, "../demo-assessment");
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const files = walk(root).map((p) => ({ path: relative(root, p).replaceAll("\\", "/"), content: readFileSync(p, "utf8") }));
const message = readFileSync(join(root, "RECRUITER_MESSAGE.txt"), "utf8");

describe("repo scanner on the demo assessment", () => {
  const r = scanFiles(files);
  const ids = new Set(r.findings.map((f) => f.ruleId));
  it("verdict is do-not-run", () => expect(r.verdict).toBe("do-not-run"));
  it.each(["npm-lifecycle-script", "env-bulk-access", "encoded-payload", "dynamic-exec", "credential-paths", "outbound-network"])("detects %s", (id) => expect(ids.has(id)).toBe(true));
  it("every finding has file, line and matched code", () => r.findings.forEach((f) => { expect(f.file).toBeTruthy(); expect(f.line).toBeGreaterThan(0); expect(f.evidence.length).toBeGreaterThan(0); }));
  it("clean code produces no findings", () => {
    expect(scanFiles([{ path: "src/a.js", content: "export const add = (a, b) => a + b;\nfetch('https://api.github.com/users')" }]).findings).toHaveLength(0);
  });
});

describe("message scanner", () => {
  const ids = scanMessage(message).map((s) => s.id);
  it.each(["run-code", "off-platform", "urgency", "high-pay", "external-link"])("flags %s", (id) => expect(ids).toContain(id));
  it("extracts the linked repo", () => expect(extractLinks(message).repos).toEqual(["prasannaraj12/decoy-demo-assessment"]));
});

describe("redaction", () => {
  it("removes names, emails, phones, keys and URL paths", () => {
    const { text, redactions } = redact(message + "\nkey AIza" + "SyA1234567890abcdefghijklmnopqrstuv and 0x52908400098527886E0F7030069857D2E4169EE7", ["Daniel"]);
    for (const secret of ["Alex", "Daniel", "daniel.recruit@example-talent.invalid", "555 0199", "AIzaSy", "0x5290"]) expect(text).not.toContain(secret);
    expect(text).toContain("https://github.com/");      // domain kept as evidence
    expect(redactions.length).toBeGreaterThan(5);
  });
  it("cloud payload never contains the raw message", () => {
    const p = cloudPayload({ message, signals: scanMessage(message), scan: scanFiles(files), repo: "x/y", userTerms: ["Alex", "Daniel"] });
    if (!p.ok) throw new Error(p.reason);
    const { text } = p.draft;
    expect(text).not.toContain("Hi Alex");
    expect(text).not.toContain("daniel.recruit");
    expect(text).toContain("scripts/setup.js:");
  });
});
