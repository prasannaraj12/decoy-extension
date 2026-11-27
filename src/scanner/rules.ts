// Deterministic indicators for malicious "coding assessment" repositories.
// Every finding comes from a rule match on a specific line — the AI only explains these, it never invents them.
//
// Patterns run over the whole file, so `\s` may cross lines. Repeats are bounded because the scanned
// repository is untrusted input.

import { isCode, isRequirements } from "./files";
import { classifyUrl } from "./url";

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";
export type Category = "Automatic execution" | "Remote code execution" | "Credential access" | "Environment harvesting" | "Dynamic code execution" | "Obfuscation" | "Command execution" | "Network destination" | "Dependency source";

export interface Rule {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** Default: code files (not docs or lockfiles). */
  files?: (path: string) => boolean;
  pattern: RegExp;
  /** Return false to ignore a match. */
  accept?: (m: RegExpMatchArray) => boolean;
  explanation: string;
  remediation: string;
}

const DONT_RUN = "Do not run this project. If you must look further, use a disposable VM with no credentials and no network.";
const REVIEW = "Read what this line does and where its inputs come from before running anything.";
const FETCHERS = "curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod";
const CALL = "(?:fetch|axios(?:\\.(?:get|post|put|patch|request))?|got(?:\\.\\w{2,6})?|request(?:\\.\\w{2,6})?|https?\\.(?:request|get)|requests\\.(?:get|post|put)|urllib\\.request\\.urlopen|needle(?:\\.\\w{2,6})?|superagent\\.\\w{2,6}|sendBeacon)";
export const NETWORK_CALL = CALL;
const notAllowed = (url: string) => !["allowed", "local"].includes(classifyUrl(url));
const inFile = (re: RegExp) => (p: string) => re.test(p);

export const RULES: Rule[] = [
  // ---------- Remote code execution ----------
  {
    id: "pipe-to-shell", title: "Downloads and runs a remote script", category: "Remote code execution", severity: "critical", confidence: "high",
    pattern: new RegExp(`\\b(?:${FETCHERS})\\b[^\\n]{0,400}?\\|\\s*(?:sudo\\s+(?:-\\S+\\s+)?)?(?:(?:/usr)?/bin/)?(?:env\\s+)?(?:(?:ba|z|da|k)?sh|cmd(?:\\.exe)?|powershell|pwsh|python3?|node|perl|ruby|php|bun|deno|iex|Invoke-Expression)\\b` +
      `|\\b(?:ba|z|da)?sh\\s+(?:-c\\s+)?["'\\\\]{0,2}(?:<\\(|\\$\\(|\`)\\s*(?:curl|wget)\\b|\\beval\\s+["'\\\\]{0,2}(?:\\$\\(|\`)\\s*(?:curl|wget)\\b`, "i"),
    explanation: "Fetches code from the internet and executes it immediately, so what runs can't be reviewed in advance.",
    remediation: DONT_RUN,
  },
  {
    id: "download-and-run", title: "Downloads a file, then runs it", category: "Remote code execution", severity: "critical", confidence: "medium",
    pattern: /\b(?:curl|wget)\b[^\n]{0,200}?\s(?:-[a-zA-Z]{0,6}[oO]|--output|--remote-name|>)\s*["']?([^\s"';&|]{1,80})["']?[\s\S]{0,300}?(?:\b(?:(?:ba|z|da)?sh|node|python3?|chmod\s+\S{1,6}|source|start)\s+["']?\1|\.\/\1)/i,
    explanation: "Saves a remote file and executes it, which is the same as piping it to a shell.",
    remediation: DONT_RUN,
  },
  {
    id: "remote-eval", title: "Evaluates code received from the network", category: "Remote code execution", severity: "critical", confidence: "high",
    pattern: new RegExp(`\\b${CALL}\\s*\\([^;]{0,300}?(?:\\b(?:eval|new\\s+Function|Function)\\s*\\(|\\.then\\s*\\(\\s*eval\\s*\\)|\\bvm\\.run)`),
    explanation: "Whoever controls the server can run any code on your machine.",
    remediation: DONT_RUN,
  },
  {
    id: "powershell-download-exec", title: "PowerShell downloads and executes code", category: "Remote code execution", severity: "critical", confidence: "high",
    pattern: new RegExp(`\\b(?:iex|Invoke-Expression)\\b[^\\n]{0,200}\\b(?:${FETCHERS}|DownloadString|Net\\.WebClient)\\b|\\b(?:DownloadString|Net\\.WebClient)\\b[^\\n]{0,300}\\|\\s*(?:iex|Invoke-Expression)\\b`, "i"),
    explanation: "A standard one-line malware loader on Windows.",
    remediation: DONT_RUN,
  },
  {
    id: "powershell-encoded", title: "Runs an encoded PowerShell command", category: "Obfuscation", severity: "critical", confidence: "high",
    pattern: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}?\s[-/]e(?:c|nc|ncodedcommand|ncoded)?\s+["'\\]{0,2}[A-Za-z0-9+/=]{8,}/i,
    explanation: "The command is encoded so it can't be read before it runs.",
    remediation: DONT_RUN,
  },
  {
    id: "windows-lolbin", title: "Hidden or policy-bypassing Windows command", category: "Command execution", severity: "high", confidence: "high",
    pattern: /\s-(?:w|windowstyle)\s+hidden\b|\s-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)\b|\bDownloadFile\s*\(|\bAdd-MpPreference\s+-Exclusion|\bSet-MpPreference\s+-Disable|\bcertutil(?:\.exe)?\s[^\n]{0,80}-urlcache|\bmshta(?:\.exe)?\s+["']?(?:https?|javascript|vbscript):|\bbitsadmin\b[^\n]{0,60}\/transfer/i,
    explanation: "Hides its window, bypasses execution policy, weakens Defender or downloads through a Windows system tool.",
    remediation: DONT_RUN,
  },
  // ---------- Automatic execution ----------
  {
    id: "vscode-auto-task", title: "Runs automatically when the folder is opened in VS Code", category: "Automatic execution", severity: "high", confidence: "high",
    files: inFile(/(^|\/)\.vscode\/[^/]+\.json$|\.code-workspace$/i),
    pattern: /"runOn"\s*:\s*"folderOpen"|"task\.allowAutomaticTasks"\s*:\s*"on"/,
    explanation: "Opening and trusting the folder is enough to execute this command.",
    remediation: "Do not choose “Trust” when opening this folder. Open it in Restricted Mode and read .vscode/ first.",
  },
  {
    id: "run-disguised-file", title: "Executes a file disguised as media or text", category: "Automatic execution", severity: "critical", confidence: "high",
    pattern: /\b(?:node|python3?|bash|sh|bun)\s+(?:--?[\w-]{1,30}\s+){0,3}["'\\]{0,2}[^\s"'|;&`\\]{1,120}\.(?:woff2?|ttf|otf|eot|svg|png|jpe?g|gif|ico|webp|css|txt|md|pdf|mp[34])\b/i,
    explanation: "Runs something named like a font, image or text file. That hides code from reviewers.",
    remediation: DONT_RUN,
  },
  // ---------- Credentials and environment ----------
  {
    id: "credential-paths", title: "References SSH keys, cloud credentials, browser or wallet data", category: "Credential access", severity: "critical", confidence: "high",
    pattern: /\.ssh[\\/]{1,2}|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws[\\/]{1,2}credentials|\.config[\\/]{1,2}(?:gcloud|solana)|\.git-credentials|\bLogin Data\b|(?:User Data|Chrome|Chromium|Brave|Edge)[^\n]{0,60}\b(?:Local State|Cookies|Web Data|Local Extension Settings)\b|\blogins\.json\b|\bkey4\.db\b|\b(?:nkbihfbeogaeaoehlefnkodbefgpgknn|ejbalbakoplchlghecdalmeeeajnimhm|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad)\b|login\.keychain|Library\/Keychains|(?:~|HOME|homedir\(\)|USERPROFILE)[^\n]{0,30}\.npmrc|Exodus[\\/]{1,2}exodus\.wallet/i,
    explanation: "A coding exercise has no reason to touch credential stores, browser profiles or crypto wallets — this is typical of info-stealer malware.",
    remediation: DONT_RUN + " If it already ran, rotate the affected credentials and move wallet funds from a clean device.",
  },
  {
    id: "wallet-browser-names", title: "Mentions a wallet, keychain or browser data name", category: "Credential access", severity: "low", confidence: "low",
    pattern: /['"`](?:MetaMask|Exodus|Phantom|Coinbase Wallet|Trust Wallet|Local State|Keychain)['"`]/i,
    explanation: "Often just a product name. It matters if the same code also reads files or sends data.",
    remediation: REVIEW,
  },
  {
    id: "env-bulk-access", title: "Reads all environment variables at once", category: "Environment harvesting", severity: "high", confidence: "high",
    pattern: /JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:keys|entries|values|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\s*\)|\b(?:in|of)\s+(?:Object\.\w{4,7}\()?process\.env\s*\)|\bos\.environ\.(?:copy|items|keys|values)\(\)|\b(?:dict|str|list|dumps)\(\s*(?:dict\()?os\.environ\s*\)|\bin\s+os\.environ\s*:|\bprintenv\b|\benv\s*>\s*[^\s=]|\b(?:gci|dir|ls|Get-ChildItem)\s+env:/,
    explanation: "Collecting every environment variable captures API keys and tokens, not just the config the app needs.",
    remediation: DONT_RUN,
  },
  {
    id: "env-spread", title: "Copies the whole environment", category: "Environment harvesting", severity: "medium", confidence: "low",
    pattern: /\.\.\.process\.env\b/,
    explanation: "Common when launching a child process, but it also copies every secret in your environment.",
    remediation: "Check where the copied object goes. It should not leave the machine.",
  },
  {
    id: "env-exfiltration", title: "Sends environment variables over the network", category: "Environment harvesting", severity: "critical", confidence: "medium",
    pattern: new RegExp(`\\b${CALL}\\s*\\([^;]{0,300}?\\b(?:process\\.env\\b(?!\\.(?:\\w{0,30}(?:URL|URI|HOST|PORT|ENDPOINT|BASE)|NODE_ENV)\\b)|os\\.environ\\b)`),
    explanation: "An environment value is passed directly into a network request.",
    remediation: "Confirm the destination and the variable. Run only with an empty, throwaway environment.",
  },
  {
    id: "dotenv-read", title: "Reads .env files directly", category: "Credential access", severity: "high", confidence: "medium",
    pattern: /readFile(?:Sync)?\([^)]{0,200}['"`][^'"`\n]{0,100}\.env['"`]|open\([^)\n]{0,100}['"]\.env['"]|\bcat\s+[^\n]{0,100}\.env\b/,
    explanation: "Reading .env files by hand (instead of loading config) is a common way to steal secrets.",
    remediation: "Remove real .env files from anywhere this project can reach.",
  },
  // ---------- Dynamic code and obfuscation ----------
  {
    id: "dynamic-exec", title: "Executes dynamically built code", category: "Dynamic code execution", severity: "high", confidence: "medium",
    pattern: /(?<![\w$.])eval\s*\(|\b(?:window|globalThis|global|self)\s*(?:\.\s*eval\b|\[\s*['"`][^'"`\n]{0,12}['"`]\s*\+)|\(\s*0\s*,\s*eval\s*\)|[=(]\s*eval\s*[;),]|\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*['"`]|\.constructor\s*\(\s*['"`]|\bconstructor\s*\.\s*constructor\b|\[\s*['"`]constructor['"`]\s*\]|\bset(?:Timeout|Interval)\s*\(\s*['"`]|\bexec\s*\(\s*(?:base64|codecs|zlib|bytes|compile|marshal)|\bvm\.(?:runIn(?:New|This)?Context|Script\b)|\bmodule\._compile\b|\b__import__\s*\(/,
    explanation: "Turns strings into running code at runtime, which hides what the program actually does.",
    remediation: REVIEW,
  },
  {
    id: "encoded-payload", title: "Decodes a hidden payload", category: "Obfuscation", severity: "medium", confidence: "medium",
    pattern: /Buffer\.from\([^)]{0,2000}?['"`](?:base64|hex)['"`]\s*\)|(?<![\w$])atob\s*\(|base64\.b64decode|FromBase64String|\bbase64\s+(?:-d|--decode|-D)\b|(?:\\x[0-9a-fA-F]{2}){16,}|(?:\\u00[0-9a-fA-F]{2}){16,}|String\.fromCharCode\((?:\s*\d{1,3}\s*,){8,}/,
    explanation: "Decoding encoded text at runtime is often used to conceal malicious code from reviewers.",
    remediation: "Decode the value without running the project and check what it contains.",
  },
  {
    id: "encoded-url", title: "Contains a base64-encoded URL", category: "Obfuscation", severity: "high", confidence: "high",
    pattern: /\baHR0c(?:HM6Ly|DovL)[A-Za-z0-9+/]{4,}={0,2}/,
    explanation: "Encoding a web address hides where the code connects.",
    remediation: "Decode the URL without visiting it. " + DONT_RUN,
  },
  {
    id: "base64-blob", title: "Large encoded blob in source", category: "Obfuscation", severity: "medium", confidence: "medium",
    pattern: /['"`][A-Za-z0-9+/]{200,}={0,2}['"`]/,
    explanation: "A long encoded string embedded in code usually hides a script or binary.",
    remediation: "Decode the value without running the project and check what it contains.",
  },
  // ---------- Commands and network ----------
  {
    id: "child-process", title: "Spawns system commands", category: "Command execution", severity: "medium", confidence: "medium",
    pattern: /['"`](?:node:)?child_process['"`]|['"`]child_['"`]\s*\+|\bexecSync\s*\(|\bspawnSync?\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(/,
    explanation: "Runs shell commands on your machine. Sometimes legitimate in build tools, rarely needed in an assessment.",
    remediation: REVIEW,
  },
  {
    id: "outbound-network", title: "Sends data to an external server", category: "Network destination", severity: "medium", confidence: "medium",
    pattern: new RegExp(`\\b${CALL}\\s*\\(\\s*(?:\\{[^{}]{0,200}?\\burl\\s*:\\s*)?["'\`](https?:\\/\\/[^"'\`\\s]{1,500})|\\bnew\\s+WebSocket\\s*\\(\\s*["'\`](wss?:\\/\\/[^"'\`\\s]{1,500})`),
    accept: (m) => notAllowed(m[1] ?? m[2]),
    explanation: "Makes a network call to a hard-coded server. Check where it goes and what data is sent.",
    remediation: "Confirm the destination belongs to a service you recognise.",
  },
  {
    id: "raw-ip-network", title: "Connects to a raw IP address", category: "Network destination", severity: "high", confidence: "high",
    pattern: /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{1,500}/i,
    accept: (m) => classifyUrl(m[0]) === "raw-ip",
    explanation: "Hard-coded IP addresses avoid domain-based blocking and are common for attacker servers.",
    remediation: DONT_RUN,
  },
  {
    id: "suspicious-host", title: "Uses a paste, tunnel or webhook service", category: "Network destination", severity: "high", confidence: "medium",
    pattern: /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{1,500}/i,
    accept: (m) => classifyUrl(m[0]) === "suspicious",
    explanation: "Anonymous hosting services are often used to stage payloads or receive stolen data.",
    remediation: DONT_RUN,
  },
  {
    id: "deceptive-url", title: "URL disguises its real destination", category: "Network destination", severity: "high", confidence: "high",
    pattern: /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{1,500}/i,
    accept: (m) => classifyUrl(m[0]) === "deceptive",
    explanation: "The part before “@” looks like a trusted site, but the connection goes to the host after it.",
    remediation: DONT_RUN,
  },
  // ---------- Python dependencies ----------
  {
    id: "pip-custom-source", title: "Installs Python packages from a custom source", category: "Dependency source", severity: "medium", confidence: "medium",
    files: isRequirements,
    pattern: /--(?:extra-)?index-url\s+\S+|--find-links\s+\S+|\bgit\+\S+|@\s*https?:\/\/\S+|^https?:\/\/\S+/m,
    explanation: "Packages from outside PyPI can run code during installation.",
    remediation: "Check the source before running pip install.",
  },
];

export const appliesTo = (rule: Rule, path: string) => (rule.files ?? isCode)(path);

/** Documentation is not executed, but copy-paste install commands are worth a look. */
export const DOC_RULES = new Set(["pipe-to-shell", "powershell-download-exec", "powershell-encoded"]);

/** npm lifecycle hooks that run during `npm install` — before you've read any code. */
export const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepublish", "dependencies"];
/** Hooks that run around an ordinary command such as `npm start`, or when packing. */
export const IMPLICIT_HOOKS = ["prestart", "poststart", "pretest", "posttest", "predev", "postdev", "prebuild", "postbuild", "prepack", "postpack", "prepublishOnly"];
/** Whole-command matches only: well-known tooling, still shown but not alarming. */
export const COMMON_HOOK_COMMANDS = /^(husky|husky install|patch-package|simple-git-hooks|lefthook install|ngcc|tsc|prisma generate|is-ci \|\| husky install)$/;
