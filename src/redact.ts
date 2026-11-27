// Deterministic redaction. Nothing reaches the cloud model unless it has passed through here
// and the user has seen the result. The brand on RedactedText makes the compiler enforce that;
// ai/consent.ts enforces it at runtime.
//
// When in doubt this over-redacts. It is pattern matching, so it cannot promise to catch every secret:
// that is why source code is never sent and why the user reviews the exact text.

export type RedactedText = string & { readonly __redacted: unique symbol };

export interface Redaction { type: string; original: string; placeholder: string; }

type Match = { text: string; groups: (string | undefined)[]; before: string };
/** Returns the replacement, or null to leave the match alone. */
type Replace = (m: Match, swap: (type: string, original: string) => string) => string | null;
interface Pass { re: RegExp; replace: Replace; }

const always = (type: string): Replace => (m, swap) => swap(type, m.text);
const pass = (type: string, re: RegExp): Pass => ({ re, replace: always(type) });

// ---------- Known secret formats. Lengths are short on purpose: pasted secrets are often cut off. ----------

const TOKENS: Pass[] = [
  pass("PRIVATE_KEY", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g),
  pass("JWT", /\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){0,2}/g),
  pass("AWS_KEY", /\b(?:AKIA|ASIA)[0-9A-Z]{8,}\b/g),
  pass("GITHUB_TOKEN", /\bgh[pousr]_[A-Za-z0-9]{6,}|\bgithub_pat_[A-Za-z0-9_]{6,}|\bglpat-[A-Za-z0-9_-]{6,}/g),
  pass("GOOGLE_KEY", /\bAIza[0-9A-Za-z_-]{6,}|\bya29\.[0-9A-Za-z_-]{6,}/g),
  pass("AI_KEY", /\bsk-(?:proj|ant|svcacct|admin|or|None)-[A-Za-z0-9_-]{4,}|\bsk-[A-Za-z0-9]{16,}|\bhf_[A-Za-z0-9]{10,}/g),
  pass("SLACK_TOKEN", /\bxox[abeoprs]-[A-Za-z0-9-]{6,}|\bxapp-[A-Za-z0-9-]{6,}/g),
  pass("STRIPE_KEY", /\b(?:sk|rk|pk|whsec)_(?:(?:live|test)_)?[A-Za-z0-9]{10,}/g),
  pass("NPM_TOKEN", /\bnpm_[A-Za-z0-9]{10,}/g),
  pass("SENDGRID_KEY", /\bSG\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g),
  pass("BOT_TOKEN", /\b\d{8,10}:[A-Za-z0-9_-]{20,}/g),
  pass("WALLET", /\b0x[a-fA-F0-9]{40}\b|\b(?:bc1|tb1|ltc1|addr1|cosmos1)[a-z0-9]{20,}|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b|\br[1-9A-HJ-NP-Za-km-z]{24,34}\b|\b[\w-]{1,63}\.(?:eth|sol)\b/g),
];
// XRP addresses ("r" + base58) always contain a digit; without that check ordinary long words would match.
TOKENS[TOKENS.length - 1].replace = (m, swap) => (/^r/.test(m.text) && !/\d/.test(m.text) ? null : swap("WALLET", m.text));

// ---------- URLs: keep the domain (evidence), drop credentials, path, query and fragment. ----------

const HOST = /^(?:[\p{L}\p{N}](?:[\p{L}\p{N}._-]*[\p{L}\p{N}])?|\[[0-9a-f:.]+\])(?::\d{1,5})?$/iu;

/** Splits trailing sentence punctuation off a URL, e.g. "https://x.com/a)." */
const trail = (s: string): [string, string] => { const t = s.match(/[.,;:!?)\]}'"]+$/)?.[0] ?? ""; return [s.slice(0, s.length - t.length), t]; };

const URLS: Pass[] = [
  pass("DATA_URI", /\bdata:[\w.+-]+\/[\w.+-]+[;,][^\s"'<>]*/gi),
  pass("FILE_PATH", /\bfile:\/\/[^\s<>"]*|\b[a-z]:\\Users\\[^\s"'<>]+|(?<![\w.])\/(?:home|Users)\/[^\s"'<>]+/gi),
  {
    re: /\b([a-z][a-z0-9+.-]{1,20}):\/\/([^\s/?#<>"'`]+)([/?#][^\s<>"]*)?/giu,
    replace: ({ text, groups: [scheme, auth = "", rawRest = ""] }, swap) => {
      const at = auth.lastIndexOf("@");
      const [rest, restTrail] = trail(rawRest);
      const [host, hostTrail] = rawRest ? [auth.slice(at + 1), ""] : trail(auth.slice(at + 1));
      // e.g. https://user:p/ss@evil.com: not a real host:port, so the split can't be trusted.
      if (!HOST.test(host)) return swap("URL", text);
      const cred = at >= 0 ? swap("URL_CREDENTIALS", auth.slice(0, at)) + "@" : "";
      const path = rest.length > 1 ? "/" + swap("URL_PATH", rest) : rest;
      return `${scheme}://${cred}${host}${hostTrail}${path}${restTrail}`;
    },
  },
  // git@github.com:owner/repo.git
  { re: /\b[\w.-]{1,40}@((?:[\w-]+\.)+[a-z]{2,24}):([^\s<>"']+)/gi, replace: ({ groups: [host, p = ""] }, swap) => `ssh://${host}/${swap("URL_PATH", p)}` },
  {
    // No scheme: t.me/name, bit.ly/x, example.com?token=…, 45.61.12.9:1244/x
    re: /(?<![\p{L}\p{N}_@./-])((?:(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[a-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?)([/?#][^\s<>"]+)/giu,
    replace: ({ groups: [host = "", rawRest = ""] }, swap) => {
      if (/\.(?:m?js|cjs|tsx?|jsx|json|md|py|sh|ya?ml)$/i.test(host)) return null; // "Node.js/React", file paths
      const [rest, t] = trail(rawRest);
      return rest.length > 1 ? `${host}/${swap("URL_PATH", rest)}${t}` : null;
    },
  },
];

// ---------- "password: x", "API_KEY=x", "Authorization: Bearer x" ----------

const ASSIGNMENTS: Pass[] = [
  // Phrases contain spaces, so take the rest of the line.
  { re: /\b((?:pass ?phrase|mnemonic|(?:seed|recovery|backup|secret) (?:phrase|words?|key|code))s?["']?\s*(?:[:=]|=>|\s(?:is|are):?\s|\s-\s)\s*)([^\n]+)/gi, replace: ({ groups: [key = "", v = ""] }, swap) => key + swap("CREDENTIAL", v) },
  // "login admin / P@ssw0rd!"
  { re: /\b((?:log-?in|creds?|credentials|user(?:name)?)\b[:=\s]+)(\S+\s*[/|]\s*\S+)/gi, replace: ({ groups: [key = "", v = ""] }, swap) => key + swap("CREDENTIAL", v) },
  // "pass hunter2", "pw - hunter2"
  { re: /\b((?:pass(?:word|code)?|pwd?)\s+(?:-\s+)?)(?=\S*\d)(\S+)/gi, replace: ({ groups: [key = "", v = ""] }, swap) => key + swap("CREDENTIAL", v) },
  {
    re: /\b(Bearer|Basic|Token)\s+(?=\S*[\d=+/])([A-Za-z0-9._~+/=-]{8,})/gi,
    replace: ({ groups: [scheme, v = ""] }, swap) => `${scheme} ${swap("CREDENTIAL", v)}`,
  },
  {
    re: /(?<![\p{L}\p{N}])([\w.-]{0,40}(?:pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credential|mnemonic)[\w.-]{0,30}(?: (?:phrase|key|code))?["']?(?:\s*(?::|=>|=|%3A|%3D|&#61;)\s*|\s+(?:is|are):?\s+))(?!https?:)("[^"\n]*"|'[^'\n]*'|\S+)/giu,
    replace: ({ groups: [key = "", v = ""] }, swap) => key + swap("CREDENTIAL", v),
  },
  {
    re: /\b((?:pw|pin|otp|passcode|cvv)\s*(?::|=|\bis\b)\s*)(\S+)/gi,
    replace: ({ groups: [key = "", v = ""] }, swap) => key + swap("CREDENTIAL", v),
  },
];

// ---------- Contact details ----------

const EMAILS: Pass[] = [
  pass("EMAIL", /[\p{L}\p{N}._%+-]{1,64}(?:@|%40|&#64;|&commat;|\s?[[({]\s?at\s?[\])}]\s?)(?:[\p{L}\p{N}-]+(?:\.|%2E|\s?[[({]\s?dot\s?[\])}]\s?))+\p{L}{2,}/giu),
  pass("EMAIL", /\b[\w.+-]{1,64} at [\w-]{1,63}(?: dot [\w-]{2,24})+\b/gi),
  pass("EMAIL", /[\p{L}\p{N}._%+-]{1,64} @ ?(?:[\p{L}\p{N}-]+\.)+\p{L}{2,}|[\p{L}\p{N}._%+-]{1,64}@ (?:[\p{L}\p{N}-]+\.)+\p{L}{2,}/giu),
  // Cut off before the TLD ("name@corpora"). Skips package versions such as vite@8.
  pass("EMAIL", /[\p{L}\p{N}._%+-]{2,64}@(?!\d|latest\b|next\b)[\p{L}\p{N}.-]{0,253}/giu),
];
const HANDLE: Pass = {
  re: /(?<![\w/@])@[A-Za-z0-9_][A-Za-z0-9_.]{2,31}(?![\w/])/g,
  replace: ({ text, before }, swap) => (before.endsWith("]") ? null : swap("HANDLE", text)), // "[URL_CREDENTIALS_1]@host"
};
/** Discord "name#1234". Before URLs, which would read it as a host with a fragment. */
const DISCORD = pass("HANDLE", /\b[\w.]{2,32}#\d{4}\b/g);

const luhn = (d: string) => [...d].reverse().reduce((s, c, i) => { let n = +c; if (i % 2 && (n *= 2) > 9) n -= 9; return s + n; }, 0) % 10 === 0;

const NUMBERS: Pass[] = [
  pass("ID_NUMBER", /\b[A-Z]{5}\d{4}[A-Z]\b/g), // Indian PAN
  // Grouped licence or recovery codes: A1B2-C3D4-E5F6
  { re: /\b[A-Z0-9]{4,6}(?:-[A-Z0-9]{4,6}){2,}\b/g, replace: ({ text }, swap) => (/\d/.test(text) && /[A-Z]/.test(text) ? swap("CREDENTIAL", text) : null) },
{
  re: /(?<![\p{L}\p{N}_/$.])(?:\+|00)?\(?\d[\d ().\t‐-―-]{6,24}\d(?![\p{L}\p{N}_])/gu,
  replace: ({ text }, swap) => {
    const digits = text.replace(/\D/g, "");
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return null;           // IPv4
    if (/^\d{4}-\d{2}-\d{2}/.test(text)) return null;                    // ISO date
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) return swap("CARD", text);
    return digits.length >= 8 && digits.length <= 15 ? swap("PHONE", text) : null;
  },
}];

// ---------- Anything that merely looks random ----------

const WORDLIKE = /^(?:[a-z]+|[A-Z]+|[A-Z][a-z]+(?:[A-Z][a-z]+)?)\d{0,4}$/;
function looksSecret(s: string, before: string): boolean {
  if (/^[0-9a-f]{32,40}$/.test(s) && /(?:commit|sha1?|rev(?:ision)?|HEAD)[\s:#=@]*$/i.test(before)) return false; // commit hash: evidence
  const parts = s.replace(/=+$/, "").split(/[-_/+]+/).filter(Boolean);
  if (parts.length >= 3 && parts.every((p) => WORDLIKE.test(p) || /^\d{1,4}$/.test(p))) return false;          // kebab-case-name-2024
  const digit = /\d/.test(s), upper = /[A-Z]/.test(s), lower = /[a-z]/.test(s);
  if (s.length >= 32 && digit && (upper || lower)) return true;
  if (s.length >= 20 && digit && upper && lower) return true;
  if (s.length >= 16 && /=$/.test(s) && upper && lower) return true;   // base64
  if (digit && upper && /^[A-Z2-7]{16,}$/.test(s)) return true;        // base32 (TOTP)
  return /^[A-Za-z]{40,}$/.test(s);
}
const generic = (re: RegExp): Pass => ({ re, replace: ({ text, before }, swap) => (looksSecret(text, before) ? swap("SECRET", text) : null) });
const SECRETS = generic(/(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{15,}={0,2}/g);
const SECRETS_IN_PATH = generic(/(?<![A-Za-z0-9+_-])[A-Za-z0-9+_-]{15,}={0,2}/g);

// ---------- Names ----------

const NOT_NAMES = new Set(("there all team everyone folks guys sir madam friend dev developer developers candidate hiring manager we i you the a an in to our your my this that it senior junior lead technical " +
  "dr mr mrs ms prof shri smt software engineer recruiter reaching looking writing excited happy glad from with at and but please thanks next also just currently").split(" "));
const NAME = "\\p{Lu}[\\p{L}'’-]+(?:[ \\t]+\\p{Lu}[\\p{L}'’-]+){0,2}";
const named = (re: RegExp): Pass => ({
  re,
  replace: ({ groups: [lead = "", name = ""] }, swap) => (NOT_NAMES.has(name.split(/\s+/)[0].toLowerCase()) ? null : lead + swap("NAME", name)),
});
const NAMES: Pass[] = [
  named(new RegExp(`(\\b(?:[Dd]r|[Mm]rs?|[Mm]s|[Pp]rof|[Ss]hri|[Ss]mt)\\.?[ \\t]+)(${NAME})`, "gu")),
  named(/(\b(?:dr|mrs?|ms|prof)\.?[ \t]+)(\p{L}{2,20})(?=\s*[,!])/giu),
  named(new RegExp(`((?:^|\\n)\\s*[\\u2013\\u2014~-]+[ \\t]*)(${NAME})(?=\\s*(?:$|\\n))`, "gu")),
  named(new RegExp(`(\\b(?:[Hh]i|[Hh]ello|[Dd]ear|[Hh]ey|HI|HELLO|DEAR|HEY|Good (?:morning|afternoon|evening))[ \\t,]+)(${NAME})`, "gu")),
  named(/^(\s*(?:hi|hello|dear|hey)\s+)(\p{L}{2,20})(?=\s*[,!])/gimu),
  named(new RegExp(`(\\b(?:I['’]?m|I am|[Mm]y name is|[Mm]y name['’]s|[Nn]ame:)\\s+)(${NAME})`, "gu")),
  named(new RegExp(`(\\b[Tt]his is\\s+)(${NAME})(?=\\s+(?:from|at|with)\\b)`, "gu")),
  named(new RegExp(`(\\b(?:[Rr]egards|[Bb]est|[Tt]hanks|[Tt]hank you|[Cc]heers|[Ss]incerely|[Ww]ishes|[Yy]ours|[Tt]ruly|[Ff]aithfully)\\s*[,.!\\n–-]\\s*)(${NAME})(?=\\s*(?:$|[\\n,.|]))`, "gu")),
];

const strip = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").normalize("NFC");
function termPasses(terms: string[]): Pass[] {
  const all = new Set(terms.flatMap((t) => { const n = normalize(t).trim(); return [n, strip(n)]; }).filter((t) => t.length > 1));
  return [...all].sort((a, b) => b.length - a.length).map((t) => {
    const esc = t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
    // Longer names also match inside handles such as "danielhart88". "_" counts as a boundary.
    const re = t.length >= 5 ? new RegExp(esc, "giu") : new RegExp(`(?<![\\p{L}\\p{N}])${esc}(?![\\p{L}\\p{N}])`, "giu");
    return pass("NAME", re);
  });
}

// ---------- Seed phrases ----------

// Common English words that are not in the BIP-39 English list. Any of them breaks up a run of candidate seed words.
const NOT_SEED = new Set("the and your for are from with our has was were his her him but not how who would could should been their its get got let may did does had than them these those".split(" "));
const WORD_RUN = /(?<![\p{L}'’-])(?:\d{1,2}[.):-]?\s*)?[a-z]{3,8}(?![\p{L}'’-])(?:[\s,;|]+(?:\d{1,2}[.):-]?\s*)?[a-z]{3,8}(?![\p{L}'’-]))+/giu;
const SEED_LABEL = /(?:(?:seed|recovery|secret|backup)\s+(?:phrase|words?|key)|mnemonic)(?:\s*(?::|=|\n|-)|\s+(?:is|are):?)\s*$/i;

/** Returns [start, end) ranges that look like a wallet recovery phrase: 12+ candidate words, or 6+ right after a label. */
function seedRanges(text: string): [number, number][] {
  const out: [number, number][] = [];
  for (const m of text.matchAll(WORD_RUN)) {
    const words = [...m[0].matchAll(/[a-z]+/gi)];
    for (let i = 0; i < words.length; ) {
      let j = i;
      while (j < words.length && !NOT_SEED.has(words[j][0].toLowerCase())) j++;
      // "…seed phrase is: w1 w2": the label itself may sit inside the run, so test after each word.
      for (let k = i; k < j; k++) {
        const start = m.index! + words[k].index!, end = m.index! + words[j - 1].index! + words[j - 1][0].length;
        const labelled = SEED_LABEL.test(text.slice(Math.max(0, start - 40), start).replace(/\d{1,2}[.):-]?\s*$/, ""));
        if (j - k >= 12 || (labelled && j - k >= 6)) { out.push([start, end]); break; }
      }
      i = j + 1;
    }
  }
  return out;
}
export const hasSeedPhrase = (input: string): boolean => seedRanges(normalize(input)).length > 0;

// ---------- Engine ----------

/** Folds look-alike forms and removes invisible characters that would split a secret. */
function normalize(s: string): string {
  return s.normalize("NFKC").replace(/[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, "")
    .replace(/(?<=[\p{L}\p{N}])[[({]\.[\])}](?=[\p{L}\p{N}])/gu, "."); // defanged "evil[.]io"
}

const PLACEHOLDER = /(\[[A-Z_]+_\d+\])/;

export interface Redactor {
  /** Free text such as a message. */
  redact(input: string): RedactedText;
  /** File paths, repository names and already-redacted text: no URL, name or "key: value" handling. Idempotent. */
  redactPath(input: string): RedactedText;
  readonly redactions: Redaction[];
}

/**
 * One redactor per payload, so placeholders stay consistent across fragments.
 * Always redact the complete source text and shorten the result afterwards: cutting first can
 * split a secret so that it no longer matches its pattern.
 */
export function createRedactor(extraTerms: string[] = []): Redactor {
  const redactions: Redaction[] = [];
  const seen = new Map<string, string>();
  const counters: Record<string, number> = {};
  const swap = (type: string, original: string) => {
    const key = type + "|" + original;
    if (!seen.has(key)) {
      counters[type] = (counters[type] ?? 0) + 1;
      const placeholder = `[${type}_${counters[type]}]`;
      seen.set(key, placeholder);
      redactions.push({ type, original, placeholder });
    }
    return seen.get(key)!;
  };

  // Placeholders are never re-scanned, so one pass cannot corrupt another's output.
  const apply = (text: string, p: Pass) => text.split(PLACEHOLDER).map((seg, i) => i % 2 ? seg
    : seg.replace(p.re, (...args: any[]) => {
        const offset = args.findIndex((a, n) => n > 0 && typeof a === "number") as number;
        return p.replace({ text: args[0], groups: args.slice(1, offset), before: (i ? "]" : "") + seg.slice(Math.max(0, args[offset] - 24), args[offset]) }, swap) ?? args[0];
      })).join("");

  const terms = termPasses(extraTerms);
  const FULL = [TOKENS[0], DISCORD, ...URLS, ...ASSIGNMENTS, ...TOKENS.slice(1), ...EMAILS, HANDLE, ...NUMBERS, SECRETS, ...terms, ...NAMES];
  const PATH = [...TOKENS, ...EMAILS, ...NUMBERS, SECRETS_IN_PATH, ...terms];

  return {
    redactions,
    redact(input) {
      let text = normalize(input);
      for (const [a, b] of seedRanges(text).reverse()) text = text.slice(0, a) + swap("SEED_PHRASE", text.slice(a, b)) + text.slice(b);
      return FULL.reduce(apply, text) as RedactedText;
    },
    redactPath: (input) => PATH.reduce(apply, normalize(input)) as RedactedText,
  };
}

export function redact(input: string, extraTerms: string[] = []): { text: RedactedText; redactions: Redaction[] } {
  const r = createRedactor(extraTerms);
  return { text: r.redact(input), redactions: r.redactions };
}
