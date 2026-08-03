/**
 * Pure sensitivity heuristics.
 *
 * These functions receive *already-resolved* strings (an absolute path, an env
 * var name). Home-directory expansion and any I/O happen in adapters; the domain
 * only pattern-matches. This keeps the rules trivially testable and Node-free.
 *
 * Matching is case-insensitive. macOS and Windows filesystems are, so
 * `~/library/keychains/login.keychain-db` opens the same file as
 * `~/Library/Keychains/login.keychain-db` — a case-sensitive list would hand
 * anyone a one-character bypass. On Linux the cost is flagging a path that does
 * not exist, which costs nothing.
 */

/**
 * Directories whose contents are secrets. Matched both as containers
 * (`~/.ssh/id_rsa`) and as the directory itself (`~/.ssh`), because *listing*
 * one is already reconnaissance: `readdir('~/.ssh')` names every key on the
 * machine, and every host in `known_hosts`, without reading a byte.
 *
 * Written without a trailing slash; the matcher adds one for the container case.
 */
const SENSITIVE_DIRECTORIES: readonly string[] = [
  // SSH, signing and cloud credentials.
  '/.ssh',
  '/.aws',
  '/.azure',
  '/.gnupg',
  '/.config/gcloud',
  '/.kube',
  '/.docker',
  // Developer-platform tokens. `gh` keeps a GitHub token in hosts.yml, which is
  // enough to push to every repository the user can.
  '/.config/gh',
  // OS credential stores. Reading these is how a stealer gets everything at
  // once, including credentials dephawk never sees pass through Node.
  '/library/keychains', // macOS, both ~/Library and /Library
  '/.local/share/keyrings', // GNOME Keyring
  '/appdata/roaming/microsoft/credentials', // Windows Credential Manager
  '/appdata/local/microsoft/vault',
  '/appdata/roaming/microsoft/protect', // DPAPI master keys
  // Crypto wallets. These dominate the npm attacks of the last two years: the
  // payload is a drainer, and the target is a key file on a developer's laptop.
  '/.ethereum/keystore', // geth
  '/.electrum/wallets',
  '/.monero',
  '/.config/solana', // solana-keygen writes id.json here
  '/.near-credentials',
  '/exodus.wallet',
  // Browser-extension storage: MetaMask, Phantom, Keplr and friends keep their
  // encrypted vaults here, keyed by extension id. A Node build step has no
  // business in any of them, so the whole directory is the rule.
  '/local extension settings',
];

/** Exact basenames that are sensitive wherever they appear. */
const SENSITIVE_BASENAMES: readonly string[] = [
  '.npmrc',
  '.env',
  '.netrc',
  '.pypirc',
  // Git storing credentials in plaintext, which `git config credential.helper
  // store` does by default.
  '.git-credentials',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
  // Bitcoin Core and the many wallets that forked it.
  'wallet.dat',
];

/**
 * Extensions that mark a file as key material by name rather than by location.
 *
 * Deliberately *not* applied inside `node_modules`: a `.pem` shipped with a
 * package is a CA bundle or a test fixture, not your secret, and flagging those
 * would make every TLS-using dependency noisy enough to be ignored.
 */
const KEY_MATERIAL_EXTENSIONS: readonly string[] = [
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.keystore',
  '.ppk',
  '.kdbx', // KeePass database
];

/** Absolute paths that are always sensitive. */
const SENSITIVE_ABSOLUTE: readonly string[] = ['/etc/passwd', '/etc/shadow'];

/**
 * Env-var secret detection, in two tiers to balance recall against noise:
 * - "strong" keywords match anywhere (a var containing SECRET/TOKEN/PASSWORD is
 *   almost certainly a secret);
 * - "weak" keywords (KEY, AUTH, …) match only as a delimited word, so common
 *   false friends like NODE_TLS_REJECT_UNAUTHORIZED (contains "AUTH") or MONKEY
 *   (contains "KEY") are not flagged.
 */
const STRONG_SECRET = /(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|APIKEY)/i;
const WEAK_SECRET = /(?:^|[_-])(KEY|KEYS|AUTH|SESSION|COOKIE|PRIVATE)(?:[_-]|$)/i;

/**
 * Normalise Windows separators, drop any trailing slash (`readdir('~/.ssh/')`
 * names the same directory as `readdir('~/.ssh')`), and lowercase so every
 * comparison below is case-insensitive.
 */
function normalisePath(path: string): string {
  const forward = path.replace(/\\/g, '/').toLowerCase();
  return forward.length > 1 ? forward.replace(/\/+$/, '') : forward;
}

function basename(path: string): string {
  const lastSlash = path.lastIndexOf('/');
  return lastSlash === -1 ? path : path.slice(lastSlash + 1);
}

/** True when a filesystem path points at something secret-bearing. */
export function isSensitivePath(path: string): boolean {
  const normalised = normalisePath(path);

  if (SENSITIVE_ABSOLUTE.includes(normalised)) {
    return true;
  }
  // Ensure a leading slash so segment matching catches paths that begin at a
  // sensitive directory (e.g. a path that literally starts with ".ssh/").
  const padded = normalised.startsWith('/') ? normalised : `/${normalised}`;

  const inSensitiveDirectory = SENSITIVE_DIRECTORIES.some(
    (directory) => padded.endsWith(directory) || padded.includes(`${directory}/`),
  );
  if (inSensitiveDirectory) {
    return true;
  }
  if (isProcEnviron(padded)) {
    return true;
  }

  const name = basename(padded);
  // `.env` and its per-environment siblings (.env.local, .env.production).
  if (SENSITIVE_BASENAMES.includes(name) || name.startsWith('.env.')) {
    return true;
  }
  return isKeyMaterial(padded, name);
}

/**
 * True for `/proc/self/environ` and `/proc/<pid>/environ`, which hand over every
 * environment variable in a single read — every secret at once, and without ever
 * touching `process.env`, so the env interceptor never sees it.
 */
function isProcEnviron(padded: string): boolean {
  return /^\/proc\/[^/]+\/environ$/.test(padded);
}

/** True when the *name* says key material, outside `node_modules`. */
function isKeyMaterial(padded: string, name: string): boolean {
  if (padded.includes('/node_modules/')) {
    return false;
  }
  return KEY_MATERIAL_EXTENSIONS.some((extension) => name.endsWith(extension));
}

/** True when an environment variable name looks like a secret. */
export function isSensitiveEnv(name: string): boolean {
  return STRONG_SECRET.test(name) || WEAK_SECRET.test(name);
}
