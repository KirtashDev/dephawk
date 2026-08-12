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
  // Terraform Cloud/Enterprise API tokens live under here (credentials.tfrc.json
  // is also matched by basename, but the directory catches the whole store).
  '/.terraform.d',
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
  // encrypted vaults here, keyed by extension id (MetaMask's `.ldb` files under
  // `nkbihfbeogaeaoehlefnkodbefgpgknn` hold the seed phrase). A Node build step
  // has no business in any of them, so the whole directory is the rule.
  '/local extension settings',
  // Browser profile directories. The npm stealers of 2025-2026 (NodeCordRAT,
  // TrapDoor, the dYdX/Polymarket drainers) go for the saved-password and
  // cookie databases inside these — `Login Data`, `Local State`, `key4.db` — so
  // both listing the profile and reading a file in it are worth catching. The
  // distinctive file names are also matched as basenames below, to catch a
  // read whatever the profile path (`Default`, `Profile 1`, …) turns out to be.
  '/.mozilla/firefox',
  '/.config/google-chrome',
  '/.config/chromium',
  '/.config/bravesoftware',
  '/.config/microsoft-edge',
  '/library/application support/firefox',
  '/library/application support/google/chrome',
  '/library/application support/bravesoftware',
  '/library/application support/microsoft edge',
];

/** Exact basenames that are sensitive wherever they appear. */
const SENSITIVE_BASENAMES: readonly string[] = [
  '.npmrc',
  '.env',
  '.netrc',
  '.pypirc',
  // Postgres password file, HashiCorp Vault token, and the Terraform Cloud
  // credential file — plaintext tokens a build step has no reason to read.
  '.pgpass',
  '.vault-token',
  'credentials.tfrc.json',
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
  // Browser credential and cookie stores, by their distinctive file names, so a
  // read is caught whatever the profile path. Chromium (Chrome/Brave/Edge and
  // Electron apps): `Login Data` is the saved-password SQLite DB and `Local
  // State` holds the AES key that decrypts it — a stealer needs both. Firefox:
  // `logins.json` + `key4.db` are the same pair; `cookies.sqlite` its cookies.
  'login data',
  'local state',
  'web data',
  'cookies.sqlite',
  'logins.json',
  'key4.db',
  'key3.db',
  'signons.sqlite',
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

/**
 * Absolute paths that are always sensitive. The `/private/…` spellings are the
 * macOS canonical form (`/etc` is a symlink to `/private/etc`): reading
 * `/private/etc/passwd` directly resolves to itself, so the `realpath` fallback
 * cannot map it back to `/etc/passwd` — both spellings have to be listed.
 */
const SENSITIVE_ABSOLUTE: readonly string[] = [
  '/etc/passwd',
  '/etc/shadow',
  '/private/etc/passwd',
  '/private/etc/shadow',
];

/**
 * Shell startup files, by basename. *Writing* one is persistence: a line
 * appended to `~/.bashrc` or `~/.zshrc` during an install runs on every shell
 * the developer opens afterwards, long after the build is gone. These are judged
 * on write only — reading a shell rc is unremarkable, but a build step that
 * modifies one is almost always malicious, and a legitimate one (a shell
 * framework installer) can allow the path explicitly.
 */
const PERSISTENCE_BASENAMES: readonly string[] = [
  // bash / sh
  '.bashrc',
  '.bash_profile',
  '.bash_login',
  '.bash_logout',
  '.profile',
  // zsh
  '.zshrc',
  '.zshenv',
  '.zprofile',
  '.zlogin',
  '.zlogout',
  // csh / ksh
  '.cshrc',
  '.tcshrc',
  '.kshrc',
  // fish
  'config.fish',
];

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
 * A variable ending in a delimited `PWD` — `MYSQL_PWD` (the MySQL client
 * password), `DB_PWD`, … A leading delimiter is required so the bare shell
 * variables `PWD` and `OLDPWD` (working-directory paths, not secrets) are not
 * flagged.
 */
const SECRET_PWD = /[_-]PWD$/i;

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
  if (isProcSensitive(padded)) {
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
 * True for the Linux `/proc` files that hand over secrets without touching the
 * interceptors' usual surfaces:
 * - `environ` — every environment variable in one read (past `process.env`).
 *   Matched at any depth so the thread form `/proc/<pid>/task/<tid>/environ`
 *   counts too, not only `/proc/<pid>/environ`.
 * - `mem` / `maps` / `pagemap` — the process address space, where every
 *   decrypted secret lives (a heap dump by another name).
 *
 * Reading these still goes through a patched `open`, so flagging the path is
 * enough even though the descriptor-based `read(fd, …)` family is not itself
 * intercepted.
 */
function isProcSensitive(padded: string): boolean {
  return /^\/proc\/.+\/(environ|mem|maps|pagemap)$/.test(padded);
}

/** True when the *name* says key material, outside `node_modules`. */
function isKeyMaterial(padded: string, name: string): boolean {
  if (padded.includes('/node_modules/')) {
    return false;
  }
  return KEY_MATERIAL_EXTENSIONS.some((extension) => name.endsWith(extension));
}

/**
 * True when *writing* `path` installs persistence — a shell startup file whose
 * modification runs attacker code on the next shell. Judged on writes only; see
 * {@link PERSISTENCE_BASENAMES}.
 */
export function isPersistenceTarget(path: string): boolean {
  return PERSISTENCE_BASENAMES.includes(basename(normalisePath(path)));
}

/** True when an environment variable name looks like a secret. */
export function isSensitiveEnv(name: string): boolean {
  return STRONG_SECRET.test(name) || WEAK_SECRET.test(name) || SECRET_PWD.test(name);
}
