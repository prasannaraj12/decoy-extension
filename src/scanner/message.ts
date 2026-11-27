import { parseRepoUrl } from "./github";

// Deterministic signals in messages: from recruiters, "IT support", colleagues or strangers.
// Nano explains these; it doesn't decide them. The assessment describes the message, never the sender.

export type SignalWeight = "weak" | "strong";
/** Signals in the same theme are not independent evidence, so they are not counted twice. */
type Theme = "execution" | "pressure" | "channel" | "authority" | "access" | "secrets";

export interface MessageSignal { id: string; title: string; quote: string; weight: SignalWeight; why: string; }

interface Signal {
  id: string; title: string; pattern: RegExp; weight: SignalWeight; theme: Theme; why: string;
  /** Strong enough on its own for high concern. */
  specific?: boolean;
}

// "Please run…", "…: Run this", or a new line starting with the action. "IT will run updates tonight" does not count.
const ASK = String.raw`(?:[.!:]\s+|\n\s*|^\s*|\b(?:[Pp]lease|[Kk]indly|[Nn]eed you to|[Yy]ou (?:need|must|have|should) to|[Cc]an you|[Cc]ould you)\s+)`;
const ACTION = String.raw`(?:[Rr]un|[Ee]xecute|[Pp]aste|[Ii]nstall|[Dd]ownload|[Dd]isable|[Vv]erify|[Ee]nter|[Tt]ype|[Oo]pen|[Uu]pdate)\b`;
const SUPPORT = String.raw`(?:\bIT\b|\b[Hh]elp ?[Dd]esk\b|\b[Ss]ervice [Dd]esk\b|\b[Tt]ech(?:nical)? [Ss]upport\b|\b(?:[Ss]ecurity|[Ss]upport) [Tt]eam\b|\b[Ss]ys ?[Aa]dmin\b)`;

const SIGNALS: Signal[] = [
  // ---------- execution ----------
  { id: "run-code", title: "Asks you to install or run their code", weight: "weak", theme: "execution", why: "Running a project also runs its install scripts. Common in normal work.", pattern: /\b(npm (i|install|ci|start|run|test)|npx \S+|yarn( install| start| dev)|pnpm (i|install|dev|start)|bun (i|install|run)|pip3? install|docker[ -]compose up|node \S+\.js|python3? \S+\.py|run (the|this|our) (project|app|script|code|demo|repo)|clone (the|this|our) (repo|repository|project))\b/i },
  { id: "trust-editor", title: "Asks you to open or trust a project in your editor", weight: "weak", theme: "execution", why: "Trusting a folder lets its editor tasks run automatically.", pattern: /\b(open|launch|import)\b[^.\n]{0,50}\b(vs ?code|visual studio code|cursor|webstorm|intellij)\b|\btrust (the )?(authors?|workspace|folder|project)\b/i },
  { id: "admin-rights", title: "Asks for administrator rights", weight: "weak", theme: "execution", why: "Elevated rights remove the limits on what a command can change. Common in setup guides.", pattern: /\brun (it )?as (an )?(admin|administrator|root)\b|\bsudo\b|\badmin(istrator)? (rights|privileges|access)\b/i },
  { id: "paste-command", title: "Asks you to paste a command into a terminal", weight: "strong", theme: "execution", why: "Pasting a command runs it with your permissions, before you can review it.", pattern: /\b(paste|copy)\b[^.\n]{0,60}\b(terminal|powershell|command prompt|cmd|run (dialog|box|window)|console)\b|\b(open|launch)\b[^.\n]{0,30}\b(terminal|powershell|command prompt)\b[^.\n]{0,40}\b(paste|run|enter|type)\b|\bwin(dows)?( key)? ?\+ ?r\b/i },
  { id: "suspicious-command", title: "Contains a command that downloads and runs code", weight: "strong", theme: "execution", why: "This command fetches code from the internet and runs it immediately, or hides what it runs. Some installers do this legitimately, so check the source.",
    pattern: /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}?\|\s*(sudo\s+)?(ba|z)?sh\b|\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,200}?\|\s*(iex|Invoke-Expression|python3?|node|powershell|pwsh|cmd)\b|\b(iex|Invoke-Expression)\b[^\n]{0,120}\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|Net\.WebClient)\b|\b(powershell|pwsh)(\.exe)?\b[^\n]{0,80}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}|\bmshta(\.exe)?\s+\S|\bcertutil(\.exe)?\b[^\n]{0,60}-(urlcache|decode)\b|\bbitsadmin\b[^\n]{0,40}\/transfer|\s-(w|windowstyle)\s+hidden\b|\bregsvr32\b[^\n]{0,30}\/i:|\b(ba)?sh\s+-c\s+["']?\$\((curl|wget)|\bbase64\s+(-d|--decode)\b[^\n]{0,30}\|\s*(ba)?sh\b/i },
  { id: "download-tool", title: "Asks you to download software for the interview", weight: "strong", theme: "execution", why: "Fake meeting apps and \"camera fixes\" are a common way to deliver malware.", pattern: /\b(download|install) (our|the|this) (meeting|video|interview|camera|driver|app|client|tool)\b|\b(camera|audio|driver) (fix|update)\b/i },
  // ---------- pressure ----------
  { id: "urgency", title: "Creates time pressure", weight: "weak", theme: "pressure", why: "Pressure discourages careful review. Deadlines are also normal.", pattern: /\b(within (24|48) hours|asap|urgent(ly)?|today only|deadline (is )?(today|tonight)|as soon as possible)\b/i },
  { id: "high-pay", title: "Unusually generous offer up front", weight: "weak", theme: "pressure", why: "An offer that seems too good lowers your guard.", pattern: /\$\s?\d{3},?\d{3}|\b\d{3}k\b|\bsigning bonus\b|\bpaid trial\b/i },
  // ---------- channel ----------
  { id: "off-platform", title: "Moves the conversation off-platform", weight: "weak", theme: "channel", why: "Moving to another app leaves the platform's protections behind. Many people use these apps normally.", pattern: /\b(telegram|whatsapp|discord|skype)\b|\b(t\.me|wa\.me|discord\.gg)\/|\b(on|via|over|to|my|using)\s+signal\b(?!\s+(processing|generation|handling|analysis|integrity))/i },
  { id: "external-link", title: "Contains a link", weight: "weak", theme: "channel", why: "Links are only a risk if they lead to code you then run.", pattern: /https?:\/\/\S+|\b[a-z0-9-]+\.(io|xyz|app|dev|link|site|online)\b/i },
  // ---------- authority ----------
  { id: "impersonation", title: "Claims authority or speaks for someone else", weight: "weak", theme: "authority", why: "A claim of authority is not proof of it. Check through a channel you already trust.",
    pattern: /\bon behalf of (your|the) (manager|ceo|cto|cfo|director|boss|team lead|lead|security team|it team|it department)\b|\b(your|the) (ceo|cto|cfo|manager|boss|director) (asked|wants|needs|requested|told)\b|\bI(?:'m| am) (from|with|calling from|contacting you from|writing from) (your |the )?(it|security|helpdesk|help desk|support|hr|finance|legal|compliance)\b|\bthis is (your |the )?(it|security|helpdesk|help desk|tech support|support) (team|department|desk)\b/i },
  { id: "it-support-pretext", title: "Presents itself as IT or support and asks you to act", weight: "strong", theme: "authority", why: "Fake support asking you to run, install or disable something is a common way in. Real IT rarely needs this by message.",
    pattern: new RegExp(`${SUPPORT}[^]{0,160}?${ASK}${ACTION}|${ASK}${ACTION}[^]{0,300}?${SUPPORT}`, "m") },
  // ---------- access ----------
  { id: "remote-access", title: "Asks for screen sharing or remote access", weight: "weak", theme: "access", why: "Screen sharing is normal in calls; giving control of your machine is not.", pattern: /\b(anydesk|teamviewer|rustdesk|remote (access|control|desktop))\b|\bshare your screen\b/i },
  { id: "unexpected-remote-access", title: "Asks you to give someone control of your computer", weight: "strong", theme: "access", why: "Remote-control tools give the other person full use of your machine and everything you are signed in to.",
    pattern: /\b(install|download|run|open|use|start|launch|accept)\b[^.\n]{0,40}\b(anydesk|teamviewer|rustdesk|quick ?assist|screenconnect|connectwise|splashtop|ultraviewer|supremo|chrome remote desktop)\b|\b(anydesk|teamviewer|quick ?assist)\b[^.\n]{0,40}\b(id|code|number|session)\b|\b(let|allow) me (to )?(connect to|access|control|take over|take control of|remote into) your (machine|computer|pc|laptop|desktop|screen)\b|\bgive me (remote )?(access|control)\b/i },
  { id: "install-certificate", title: "Asks you to install a certificate or device profile", weight: "weak", theme: "access", why: "A trusted certificate or profile can let someone read or change your traffic. Legitimate only through your company's normal process.",
    pattern: /\b(install|import|trust|add|accept)\b[^.\n]{0,40}\b((root|ca|security|ssl|tls|proxy|company|corporate|vpn) )?(certificate|cert)s?\b|\b(install|import|add)\b[^.\n]{0,40}(\.(cer|crt|pem|p12|pfx)\b|\b(configuration|mdm|device management) profile\b|\.mobileconfig\b)/i },
  // ---------- secrets ----------
  { id: "disable-security", title: "Asks you to weaken security", weight: "strong", theme: "secrets", specific: true, why: "There is rarely a good reason to switch off protection at someone's request.",
    pattern: /\b(disable|turn off|switch off|uninstall|pause|stop) (your |the |windows )?(antivirus|anti-virus|firewall|defender|security software|endpoint protection|real-?time protection|edr|smartscreen)\b|\badd (an )?exclusion\b[^.\n]{0,30}\b(defender|antivirus)\b/i },
  { id: "credential-request", title: "Asks for a password, code or recovery phrase", weight: "strong", theme: "secrets", specific: true, why: "Nobody legitimate needs your password, one-time code or seed phrase.",
    pattern: /(?<!\b(never|not|don't|do not|won't|will never|shouldn't|should never)\s+(\w+\s+)?)\b(send|share|give|tell|provide|confirm|read (out|back)|forward|reply with|dm)\b( me| us)?[^.\n]{0,40}\b(password|passcode|one[- ]time (code|password)|otp|2fa code|mfa code|verification code|auth(entication)? code|seed phrase|recovery phrase|secret (recovery )?phrase|private key)s?\b/i },
  { id: "crypto-wallet", title: "Mentions wallets or seed phrases", weight: "weak", theme: "secrets", why: "Normal in crypto work; a risk when combined with a request to run code.", pattern: /\b(seed phrase|private key|metamask|wallet (address|extension)|connect your wallet)\b/i },
];

const BY_ID = new Map(SIGNALS.map((s) => [s.id, s]));
/** "Asks you…" for use mid-sentence; acronyms such as IT keep their case. */
const inline = (t: string) => t.charAt(0).toLowerCase() + t.slice(1);

export function scanMessage(text: string): MessageSignal[] {
  const out: MessageSignal[] = [];
  for (const s of SIGNALS) {
    const m = text.match(s.pattern);
    if (m) {
      const start = Math.max(0, (m.index ?? 0) - 40);
      out.push({ id: s.id, title: s.title, weight: s.weight, why: s.why, quote: text.slice(start, (m.index ?? 0) + m[0].length + 40).replace(/\s+/g, " ").trim() });
    }
  }
  return out;
}

export type ConcernLevel = "low" | "worth-checking" | "high";
export interface LinkedRepo { slug: string; verdict: string; complete: boolean; }
export interface MessageAssessment { level: ConcernLevel; summary: string; reasons: string[]; signalIds: string[]; }

/**
 * Combines signals into one level. Not a count: signals in the same theme are one piece of evidence, weak signals
 * alone never reach high concern, and a repository only counts if it was fully scanned.
 */
export function assessMessage(signals: MessageSignal[], ctx: { seedPhrase?: boolean; linkedRepos?: LinkedRepo[] } = {}): MessageAssessment {
  const known = signals.map((s) => ({ s, def: BY_ID.get(s.id) })).filter((x) => x.def);
  const strong = known.filter((x) => x.def!.weight === "strong");
  const themes = new Set(known.map((x) => x.def!.theme));
  const strongThemes = new Set(strong.map((x) => x.def!.theme));
  const has = (id: string) => known.some((x) => x.s.id === id);
  const reasons: string[] = [];

  if (ctx.seedPhrase) reasons.push("The message appears to contain a wallet recovery phrase.");
  for (const x of known.filter((x) => x.def!.specific)) reasons.push(`${x.def!.title}.`);
  const badRepo = (ctx.linkedRepos ?? []).find((r) => r.complete && r.verdict === "do-not-run");
  if (badRepo) reasons.push(`It links to ${badRepo.slug}, which a full scan rated "Do not run".`);
  if (strongThemes.size >= 2) reasons.push(`Independent warning signs: ${strong.map((x) => inline(x.def!.title)).join("; ")}.`);
  if (reasons.length) return { level: "high", summary: "High concern. Do not act on this message until you have checked it through a channel you already trust.", reasons, signalIds: known.map((x) => x.s.id) };

  if (strong.length) reasons.push(`${strong[0].def!.title}. Check the source and what it would run before going ahead.`);
  if (has("run-code") && (has("urgency") || has("off-platform"))) reasons.push("A request to run code, combined with time pressure or a move to another app.");
  if (has("install-certificate") && (themes.has("channel") || themes.has("pressure") || themes.has("authority"))) reasons.push("A certificate or profile request that arrives with a link, pressure or a claim of authority.");
  if (themes.size >= 3) reasons.push(`Several kinds of warning sign together (${known.map((x) => inline(x.def!.title)).join("; ")}).`);
  if (reasons.length) return { level: "worth-checking", summary: "Worth checking. Some requests here need a closer look before you act.", reasons, signalIds: known.map((x) => x.s.id) };

  return {
    level: "low",
    summary: known.length ? "Low concern. Only signals that are common in normal work were found. That isn't proof it's safe." : "Low concern. No warning signs were found. That isn't proof it's safe.",
    reasons: [], signalIds: known.map((x) => x.s.id),
  };
}

/** Links and GitHub repos mentioned in a message — used to link message → repo on the timeline. */
export function extractLinks(text: string): { urls: string[]; repos: string[] } {
  const urls = [...text.matchAll(/https?:\/\/[^\s)>\]"']+/gi)].map((m) => m[0].replace(/[.,;:!?]+$/, ""));
  // Also "github.com/owner/repo" without a scheme. parseRepoUrl checks the host exactly.
  const bare = [...text.matchAll(/(?<![\w@./-])(?:www\.)?github\.com\/[^\s)>\]"']+|\bgit@github\.com:[^\s)>\]"']+/gi)].map((m) => m[0]);
  const repos = [...new Set([...urls, ...bare].map(parseRepoUrl).filter((r) => !!r).map((r) => `${r!.owner}/${r!.repo}`.toLowerCase()))];
  return { urls, repos };
}
