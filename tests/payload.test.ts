import { describe, it, expect } from "vitest";
import { cloudPayload } from "../src/ai/prompts";
import { scanMessage } from "../src/scanner/message";
import { scanFiles } from "../src/scanner/scan";

const build = (opts: Parameters<typeof cloudPayload>[0]) => { const p = cloudPayload(opts); if (!p.ok) throw new Error(p.reason); return p.draft; };
const fromMessage = (message: string, userTerms: string[] = []) => build({ message, signals: scanMessage(message), userTerms }).text;
const fromCode = (content: string) => build({ scan: scanFiles([{ path: "a.js", content }]) }).text;

// The old code cut evidence to a window and redacted afterwards, so a secret straddling the edge
// leaked. Slide each secret across both edges of the window, one character at a time.
describe("secrets straddling the excerpt edge never reach the cloud payload", () => {
  // Fake values, split so that secret scanners don't mistake this file for a leak.
  const SECRETS: [string, string, string[]][] = [
    ["email", "secretperson.name@bigcorp.com", ["secretperson", "secretp"]],
    ["google key", "AIza" + "SyA1234567890abcdefghijklmnopqrstuv", ["AIza", "ghijklmn", "nopqrstuv"]],
    ["github token", "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789", ["ghp_", "klmnop", "456789"]],
    ["eth address", "0x52908400098527886E0F7030069857D2E4169EE7", ["0x5290", "69857D2E", "4169EE7"]],
    ["url path", "https://evil.example/private/tracking-id-777", ["tracking-id", "777"]],
  ];
  it.each(SECRETS)("%s in a message", (_n, secret, parts) => {
    for (let pad = 0; pad <= 60; pad++) {
      const filler = "z".repeat(pad);
      for (const msg of [`npm install ${filler} ${secret} end`, `start ${secret} ${filler} npm install`]) {
        const text = fromMessage(msg);
        for (const p of parts) expect(text, `pad=${pad}`).not.toContain(p);
      }
    }
  });
});

describe("cloud payload", () => {
  it("redacts a user-supplied name cut by the excerpt window", () => {
    for (let pad = 0; pad <= 60; pad++) expect(fromMessage(`npm install ${"z".repeat(pad)} Harshini ok`, ["Harshini"])).not.toMatch(/Hars|shini/);
  });
  it("withholds quotes when the full message is not supplied", () => {
    const msg = "npm install then mail a.person@corp.com";
    const { text } = build({ signals: scanMessage(msg) });
    expect(text).toContain("(quote withheld)");
    expect(text).not.toContain("a.person");
  });
  it("sends rule, severity, file and line for a finding, and no source code", () => {
    const text = fromCode('const a = 1;\neval("CODE_CANARY password=hunter2")');
    expect(text).toContain("- [high] dynamic-exec (Dynamic code execution) — a.js:2");
    expect(text).not.toMatch(/CODE_CANARY|hunter2|eval\(/);
  });
  it("sends no source code for lifecycle hooks or very long lines either", () => {
    const { text } = build({ scan: scanFiles([
      { path: "package.json", content: '{"scripts":{"postinstall":"node CODE_CANARY.js"}}' },
      { path: "b.js", content: `x("CODE_CANARY${"k".repeat(3000)}")` },
    ]) });
    expect(text).toContain("npm-lifecycle-script");
    expect(text).toContain("obfuscated-line");
    expect(text).not.toContain("CODE_CANARY");
  });
  it("redacts file paths and the repository name", () => {
    const { text } = build({ scan: scanFiles([{ path: "me@corp.com/a.js", content: "eval(x)" }]), repo: "harshini/private", userTerms: ["harshini"] });
    expect(text).not.toContain("me@corp.com");
    expect(text).not.toContain("harshini");
  });
  it("uses one consistent placeholder per value, and distinct ones for distinct values", () => {
    const message = "npm install, mail one@corp.com now";
    const { text, redactions } = build({ message, signals: scanMessage(message), scan: scanFiles([{ path: "one@corp.com/two@corp.com.js", content: "eval(x)" }]) });
    const byPlaceholder = new Map(redactions.map((r) => [r.placeholder, r.original]));
    expect(byPlaceholder.size).toBe(redactions.length);
    expect(byPlaceholder.get("[EMAIL_1]")).toBe("one@corp.com");
    expect(text).toContain("[EMAIL_1]/[EMAIL_2]:1");
  });
  it.each([
    ["plain", "npm install. My seed phrase is abandon ability able about above absent absorb abstract absurd abuse access accident"],
    ["numbered", "npm install\n1. abandon 2. ability 3. able 4. about 5. above 6. absent 7. absorb 8. abstract 9. absurd 10. abuse 11. access 12. accident"],
    ["one per line", "npm install\nabandon\nability\nable\nabout\nabove\nabsent\nabsorb\nabstract\nabsurd\nabuse\naccess\naccident"],
    ["partial, labelled", "npm install. recovery phrase: abandon ability able about above absent"],
  ])("refuses to build any payload for a seed phrase (%s)", (_n, message) => {
    expect(cloudPayload({ message, signals: scanMessage(message) })).toEqual({ ok: false, reason: expect.stringContaining("seed") });
  });
  it("tells the model when the scan was incomplete", () => {
    const scan = scanFiles([{ path: "a.js", content: "1" }], { issues: [{ kind: "download-failed", path: "b.js", detail: "HTTP 500" }] });
    expect(build({ scan }).text).toContain("verdict incomplete (INCOMPLETE: 1");
  });
  it("still carries useful evidence", () => {
    const text = fromMessage("Please clone https://github.com/o/r and run npm install within 24 hours");
    expect(text).toContain("https://github.com/");
    expect(text).toContain("npm install");
  });
});
