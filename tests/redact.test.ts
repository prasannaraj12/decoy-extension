import { describe, it, expect } from "vitest";
import { createRedactor, hasSeedPhrase, redact } from "../src/redact";

const R = (s: string, terms?: string[]) => redact(s, terms).text as string;

describe("removes secrets", () => {
  it.each<[string, string, string[]]>([
    // contact details
    ["email", "mail a.person+x@corp.co.in now", ["a.person", "corp.co.in"]],
    ["email, cut before the TLD", "mail secretperson.name@verylongcom", ["secretperson", "verylongcom"]],
    ["email, cut after @", "mail secretperson.name@", ["secretperson"]],
    ["email, percent-encoded", "mail secretperson%40corp.com", ["secretperson", "corp"]],
    ["email, html-encoded", "mail secretperson&#64;corp.com", ["secretperson"]],
    ["email, [at] [dot]", "mail secretperson [at] corp [dot] com", ["secretperson", "corp"]],
    ["email, spelled out", "mail secretperson at corp dot com", ["secretperson"]],
    ["email, full-width @", "mail secretperson＠corp.com", ["secretperson"]],
    ["email, zero-width split", "mail secret\u200Bperson@corp.com", ["person@", "corp.com"]],
    ["Indian mobile +91 5-5", "call +91 98765 43210", ["98765", "43210"]],
    ["Indian mobile, hyphen", "call +91-98765-43210", ["98765", "43210"]],
    ["Indian mobile, bare", "call 9876543210 ok", ["9876543210"]],
    ["Indian mobile, 0 prefix", "call 09876543210", ["9876543210"]],
    ["US phone", "call (415) 555-0199 today", ["415", "555", "0199"]],
    ["UK phone", "call +44 20 7946 0958", ["7946", "0958"]],
    ["phone, 00 prefix, dots", "call 0049.30.1234567", ["1234567"]],
    ["phone, non-breaking hyphen", "call +1 415\u2011555\u20110199", ["555", "0199"]],
    ["card number", "card 4111 1111 1111 1111", ["4111", "1111"]],
    ["Telegram link", "t.me/decoy_demo_recruiter", ["decoy_demo", "recruiter"]],
    ["Telegram link, query", "t.me/joinchat?x=secrettoken", ["secrettoken", "joinchat"]],
    ["Telegram deep link", "tg://resolve?domain=decoy_demo_recruiter", ["decoy_demo"]],
    ["handle", "ping @daniel_hart on Telegram", ["daniel_hart"]],
    ["Discord tag", "ping daniel.hart#1234", ["daniel.hart"]],
    // keys and tokens: fake values, split so that secret scanners don't mistake this file for a leak
    ["OpenAI project key", "sk-proj-" + "abc123DEF456ghi789", ["abc123", "ghi789"]],
    ["OpenAI project key, cut", "sk-proj-abc1", ["abc1"]],
    ["Anthropic key", "sk-ant-" + "api03-abcDEF123", ["api03", "abcDEF"]],
    ["Google key", "AIza" + "SyA1234567890abcdefghijklmnopqrstuv", ["AIza", "qrstuv"]],
    ["Google key, cut", "AIzaSyA1234", ["SyA1234"]],
    ["GitHub token, cut", "ghp_abcdef12", ["abcdef12"]],
    ["AWS key id, cut", "AKIA" + "IOSFODNN", ["IOSFODNN"]],
    ["AWS secret key", "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY", ["wJalr", "bPxRfi", "EXAMPLEKEY"]],
    ["npm token", "npm_" + "abcdefghijklmnop", ["abcdefghij"]],
    ["Slack token", "xoxb-" + "12345-abcde", ["12345-abcde"]],
    ["Stripe key", "sk_live_" + "abcdefghijkl", ["abcdefghijkl"]],
    ["JWT, header only", "eyJhbGciOiJIUzI1NiJ9", ["hbGci"]],
    ["Telegram bot token", "123456789:" + "FAKEfakeFAKEfakeFAKE_not-a-real-token1", ["FAKEfake", "real-token"]],
    ["private key block", "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEabc\n-----END RSA " + "PRIVATE KEY-----", ["MIIE"]],
    ["private key block, cut", "-----BEGIN " + "PRIVATE KEY-----\nMIIEabc\nshort", ["MIIE", "short"]],
    ["base64 value", "c2VjcmV0QGNvcnAuY29t", ["c2VjcmV0"]],
    ["TOTP secret", "JBSWY3DPEHPK3PXPJBSW", ["JBSWY3"]],
    ["hex secret", "deadbeef0123456789abcdef01234567", ["deadbeef"]],
    ["ETH private key", "0x" + "ab12".repeat(16), ["ab12ab12"]],
    // assignments
    ["password:", "password: hunter2", ["hunter2"]],
    ["password is", "the password is hunter2 ok", ["hunter2"]],
    ["quoted password with spaces", 'password = "correct horse battery"', ["correct", "horse", "battery"]],
    ["env style", "DB_PASSWORD=hunter2 API_KEY=abc123", ["hunter2", "abc123"]],
    ["JSON style", '{"client_secret":"abc"}', [':"abc"']],
    ["percent-encoded assignment", "api_key%3Dabc123", ["abc123"]],
    ["bearer", "Authorization: Bearer abc.def-123", ["abc.def"]],
    ["OTP", "OTP: 482913", ["482913"]],
    ["password, no separator", "use pass hunter2", ["hunter2"]],
    ["password, dash", "My pw - hunter2", ["hunter2"]],
    ["login pair", "login admin / P@ssw0rd!", ["P@ss", "admin"]],
    ["multi-word passphrase", "passphrase: correct horse battery staple", ["correct", "horse", "staple"]],
    ["recovery code", "A1B2-C3D4-E5F6-G7H8", ["A1B2", "G7H8"]],
    ["PAN number", "PAN ABCDE1234F", ["ABCDE1234F"]],
    ["data URI", "data:text/plain;base64,c2VjcmV0", ["c2Vj"]],
    ["email with spaces", "mail secretperson @ corp.com", ["secretperson", "corp.com"]],
    ["title", "Hello Dr. Priya Sharma", ["Priya", "Sharma"]],
    ["lowercase title", "dear ms sharma, hi", ["sharma"]],
    ["dash sign-off", "thanks\n— Priya", ["Priya"]],
    ["yours", "Yours, Priya", ["Priya"]],
    ["defanged URL", "evil[.]io/secret", ["secret"]],
    ["password containing @", "password=ab@cd.com!tail", ["ab@cd", "tail"]],
    // URLs
    ["URL path and query", "https://evil.io/private/id?token=abc#frag", ["private", "abc", "frag"]],
    ["URL query without a path", "https://evil.io?token=abc", ["abc"]],
    ["uppercase URL", "HTTPS://EVIL.IO/Secret/Abc", ["Secret", "Abc"]],
    ["URL credentials", "https://user:pa55@evil.io/x", ["user", "pa55"]],
    ["URL credentials with a slash", "https://user:pa/ss@evil.io/x", ["user:pa", "ss@"]],
    ["websocket URL", "wss://evil.io/socket/abc", ["socket"]],
    ["URL without a scheme", "bit.ly/Abc123", ["Abc123"]],
    ["IP URL without a scheme", "45.61.12.9:1244/pdown", ["pdown"]],
    ["ssh git URL", "git@github.com:harshini/private.git", ["harshini", "private"]],
    ["file URL", "file:///C:/Users/harshini/x.txt", ["harshini"]],
    ["Windows home path", "C:\\Users\\harshini\\secrets.txt", ["harshini"]],
    ["Unix home path", "see /home/harshini/.ssh", ["harshini"]],
    // wallets
    ["ETH address", "0x52908400098527886E0F7030069857D2E4169EE7", ["0x5290"]],
    ["BTC address", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", ["bc1q"]],
    ["Solana address", "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtVv", ["7EcDh"]],
    ["ENS name", "send to harshini.eth", ["harshini"]],
    // names
    ["greeting", "Hi Alex, welcome", ["Alex"]],
    ["lowercase greeting", "hi alex, welcome", ["alex"]],
    ["accented greeting", "Hi José, welcome", ["José"]],
    ["introduction", "I'm Daniel Hart, technical recruiter", ["Daniel", "Hart"]],
    ["sign-off", "Regards, Priya Sharma", ["Priya", "Sharma"]],
    ["sign-off on its own line", "Best regards,\nPriya Sharma\nExample Talent", ["Priya", "Sharma"]],
  ])("%s", (_n, input, gone) => {
    for (const g of gone) expect(R(input)).not.toContain(g);
  });

  it.each<[string, string, string[], string[]]>([
    ["plain", "Contact Harshini now", ["Harshini"], ["Harshini"]],
    ["any case", "contact HARSHINI now", ["Harshini"], ["HARSHINI"]],
    ["accented, supplied by the user", "Contact José now", ["José"], ["José"]],
    ["accent dropped in the text", "Contact Jose now", ["José"], ["Jose"]],
    ["decomposed accents", "Contact Jose\u0301 now", ["José"], ["Jose"]],
    ["non-Latin", "Contact ஹர்ஷினி now", ["ஹர்ஷினி"], ["ஹர்ஷினி"]],
    ["inside a handle", "ping harshini14muthu", ["Harshini"], ["harshini"]],
    ["joined by underscore", "raj_k is here", ["Raj"], ["raj"]],
    ["regex characters", "Contact A.B (x) now", ["A.B (x)"], ["A.B (x)"]],
  ])("user-supplied name: %s", (_n, input, terms, gone) => {
    for (const g of gone) expect(R(input, terms)).not.toContain(g);
  });
});

describe("keeps security evidence", () => {
  it.each<[string, string, string[]]>([
    ["domain", "https://evil-site.example/a/b", ["https://evil-site.example/"]],
    ["domain behind credentials", "https://user:pw@evil.io/x", ["evil.io"]],
    ["domain and port", "http://45.61.12.9:1244/pdown", ["45.61.12.9:1244"]],
    ["Telegram domain", "t.me/daniel", ["t.me/"]],
    ["uppercase domain", "HTTPS://EVIL.IO/x", ["EVIL.IO"]],
    ["commit hash", "pinned to commit 3f786850e387550fdab836ed7e6dc881de23001b", ["3f786850e387550fdab836ed7e6dc881de23001b"]],
    ["IPv4", "beacon to 45.61.12.9 now", ["45.61.12.9"]],
    ["date", "by 2026-11-25 10:30", ["2026-11-25"]],
    ["kebab-case file name", "node scripts/very-long-setup-script-name-number-2024-final.js", ["very-long-setup-script-name-number-2024-final.js"]],
    ["package versions and scopes", "npm i vite@8.3.8 @types/node", ["vite@8.3.8", "@types/node"]],
    ["defanged domain", "hxxps://evil[.]io/a", ["evil.io"]],
    ["salary and company", "Example Talent is hiring, $220,000 base", ["Example Talent is hiring, $220,000 base"]],
    ["commands", "run npm install and npm start", ["npm install", "npm start"]],
    ["technology lists", "React/TypeScript/Node18/AWS stack", ["React/TypeScript/Node18/AWS"]],
    ["job titles after I'm", "I'm Senior Recruiter", ["Senior Recruiter"]],
  ])("%s", (_n, input, kept) => {
    for (const k of kept) expect(R(input)).toContain(k);
  });
  it("only keeps a 40-hex value when it is labelled as a commit", () => {
    expect(R("value 3f786850e387550fdab836ed7e6dc881de23001b")).not.toContain("3f78");
  });
  it("does not swallow text after a URL", () => {
    expect(R("see https://evil.io/a, then run npm install")).toMatch(/evil\.io\/\[URL_PATH_1\], then run npm install/);
  });
});

describe("seed phrases", () => {
  const words = "abandon ability able about above absent absorb abstract absurd abuse access accident".split(" ");
  it.each([
    ["12 words", words.join(" ")], ["numbered", words.map((w, i) => `${i + 1}. ${w}`).join(" ")], ["comma separated", words.join(", ")],
    ["one per line", words.join("\n")], ["upper case", words.join(" ").toUpperCase()], ["24 words", [...words, ...words].join(" ")],
    ["inside a sentence", `please use ${words.join(" ")} for the test`], ["labelled, partial", `seed phrase: ${words.slice(0, 6).join(" ")}`],
    ["zero-width split", words.join(" ").replace("ability", "abi\u200Blity")],
  ])("detected: %s", (_n, text) => {
    expect(hasSeedPhrase(text)).toBe(true);
    expect(R(text).toLowerCase()).not.toMatch(/abandon|absorb|absent/);
  });
  it.each([
    "Please run this command from your terminal and then send the output to our team when it is done.",
    "Never share your seed phrase with anyone. Connect your wallet to continue with the interview process.",
    "We loved your profile and are hiring a Senior Blockchain Engineer, fully remote, with a short take-home this week.",
  ])("not triggered by ordinary text: %s", (text) => expect(hasSeedPhrase(text)).toBe(false));
});

describe("engine", () => {
  it("reuses one placeholder per value across calls", () => {
    const r = createRedactor();
    expect(r.redact("a1@corp.com b2@corp.com")).toBe("[EMAIL_1] [EMAIL_2]");
    expect(r.redact("b2@corp.com")).toBe("[EMAIL_2]");
  });
  it("redactPath is idempotent and leaves file paths readable", () => {
    const r = createRedactor(["Harshini"]);
    expect(r.redactPath("src/lodash.merge/token.js:12")).toBe("src/lodash.merge/token.js:12");
    const once = r.redactPath("harshini/me@corp.com/a.js");
    expect(once).not.toMatch(/harshini|corp/);
    expect(r.redactPath(once)).toBe(once);
  });
  it("handles large hostile input quickly", () => {
    const t0 = performance.now();
    for (const s of ["a".repeat(50_000), "a-".repeat(25_000), "1 ".repeat(25_000), "a.".repeat(25_000), "@".repeat(50_000), "word ".repeat(10_000), "https://".repeat(6_000), "password".repeat(6_000), "x@".repeat(25_000)]) redact(s, ["Harshini"]);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});
