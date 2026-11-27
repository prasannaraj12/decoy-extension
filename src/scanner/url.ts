// URL classification with the platform URL parser, so userinfo tricks and encoded IPs are resolved the way a browser would.

const ALLOWED_HOSTS = ["registry.npmjs.org", "registry.yarnpkg.com", "api.github.com", "example.com", "example.org", "jsonplaceholder.typicode.com", "pypi.org"];
/** Anyone can publish content here, so only these GitHub pages count as ordinary destinations. */
const GITHUB_UGC_PATH = /^\/[^/]+\/[^/]+\/(raw|releases\/download|archive|suites)\//;

/** Anonymous paste, JSON-bin, tunnel and webhook services: common for payload staging and exfiltration. */
const SUSPICIOUS_HOSTS = ["pastebin.com", "hastebin.com", "paste.ee", "rentry.co", "ghostbin.com", "jsonkeeper.com", "jsonsilo.com", "npoint.io", "mocki.io", "jsonbin.io", "run.mocky.io",
  "webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "localhost.run",
  "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "catbox.moe", "0x0.st", "oast.fun", "oast.pro", "interact.sh", "burpcollaborator.net"];

const under = (host: string, list: string[]) => list.some((h) => host === h || host.endsWith("." + h));

export type UrlClass = "allowed" | "local" | "raw-ip" | "suspicious" | "deceptive" | "other";

function ipv4Class(h: string): "local" | "raw-ip" | null {
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const [a, b] = [+m[1], +m[2]];
  return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) ? "local" : "raw-ip";
}

export function classifyUrl(raw: string): UrlClass {
  let u: URL;
  // ws(s) parses like http(s). Template strings such as https://${host} don't parse: treat as unknown.
  try { u = new URL(raw.replace(/^ws/i, "http")); } catch { return "other"; }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  // "https://github.com@evil.xyz": reads as one site, goes to another.
  if ((u.username || u.password) && /\./.test(decodeURIComponent(u.username))) return "deceptive";
  if (host === "localhost" || host.endsWith(".localhost") || host === "[::1]") return "local";
  const ip = ipv4Class(host);
  if (ip) return ip;
  if (host.startsWith("[")) return "raw-ip";
  if (under(host, SUSPICIOUS_HOSTS)) return "suspicious";
  if ((host === "discord.com" || host === "discordapp.com") && u.pathname.startsWith("/api/webhooks")) return "suspicious";
  if (host === "api.telegram.org" && u.pathname.startsWith("/bot")) return "suspicious";
  if (u.username || u.password) return "other";
  if (host === "github.com") return GITHUB_UGC_PATH.test(u.pathname) ? "other" : "allowed";
  return under(host, ALLOWED_HOSTS) ? "allowed" : "other";
}

export const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]+/gi;
