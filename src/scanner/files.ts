// What kind of file is this? Used by the fetcher (what to download) and the scanner (which rules apply).

/** Media that no tool executes by itself. Not inspected, but always counted and shown. */
const ASSET = /\.(png|jpe?g|gif|bmp|webp|avif|ico|icns|woff2?|ttf|otf|eot|mp3|mp4|m4a|webm|wav|ogg|mov|pdf|psd)$/i;
/** Can carry executable code but can't be read as text: makes the scan incomplete. */
const OPAQUE = /\.(exe|dll|so|dylib|node|wasm|jar|class|war|apk|bin|o|a|lib|msi|dmg|pkg|deb|rpm|zip|tgz|gz|tar|bz2|xz|7z|rar|whl|egg|pyc|pyo|asar|scr|com|lnk|iso|img)$/i;
const LOCK = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/i;
const OTHER_LOCK = /(^|\/)(bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|go\.sum|deno\.lock)$/i;
const REQUIREMENTS = /(^|\/)[^/]*requirements[^/]*\.(txt|in)$/i;
const DOC = /\.(md|mdx|markdown|rst|adoc|txt|csv|tsv|log)$|(^|\/)(LICEN[CS]E|NOTICE|AUTHORS|CONTRIBUTORS|CHANGELOG|CODEOWNERS|COPYING)$|(^|\/)\.(git|docker|npm|eslint|prettier|vscode)ignore$|(^|\/)\.gitattributes$/i;
const GENERATED = /(^|\/)(dist|build|out|\.next|\.nuxt|coverage|node_modules|vendor|bower_components)\/|\.(min|bundle|chunk)\.[cm]?js$/i;

export const isAsset = (p: string) => ASSET.test(p);
export const isOpaque = (p: string) => OPAQUE.test(p);
export const isLockfile = (p: string) => LOCK.test(p);
export const isPackageJson = (p: string) => /(^|\/)package\.json$/i.test(p);
export const isDoc = (p: string) => DOC.test(p) && !REQUIREMENTS.test(p);
export const isGenerated = (p: string) => GENERATED.test(p);
export const isRequirements = (p: string) => REQUIREMENTS.test(p);
/** Everything that isn't documentation or a lockfile, including extensionless scripts. */
export const isCode = (p: string) => !isDoc(p) && !LOCK.test(p) && !OTHER_LOCK.test(p);
export const isJs = (p: string) => /\.([cm]?[jt]sx?)$/i.test(p);
export const isShellLike = (p: string) => /\.(sh|bash|zsh|ya?ml)$|(^|\/)(Dockerfile[^/]*|Makefile|\.husky\/[^/]+)$/i.test(p) || !/\.[^/]+$/.test(p);

export const MAX_FILE_BYTES = 1_000_000;
export const MAX_LOCKFILE_BYTES = 8_000_000;
export const maxBytes = (p: string) => (isLockfile(p) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES);

/** Lower is downloaded first, so limits never push out the files that execute on install or open. */
export function priority(p: string): number {
  if (isPackageJson(p) || /(^|\/)(\.npmrc|\.yarnrc[^/]*|binding\.gyp|setup\.py|pyproject\.toml)$/i.test(p) || /(^|\/)\.(vscode|devcontainer|husky)\//i.test(p)) return isGenerated(p) ? 5 : 0;
  if (isGenerated(p)) return /(^|\/)node_modules\//.test(p) ? 6 : 4;
  if (isLockfile(p)) return 3;
  return isCode(p) ? 1 : 2;
}
