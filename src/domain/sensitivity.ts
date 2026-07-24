/**
 * Pure sensitivity heuristics.
 *
 * These functions receive *already-resolved* strings (an absolute path, an env
 * var name). Home-directory expansion and any I/O happen in adapters; the domain
 * only pattern-matches. This keeps the rules trivially testable and Node-free.
 */

/**
 * Path fragments that, when present in a resolved path, mark it sensitive.
 * We match on normalised forward-slash segments so the same list works on
 * POSIX and Windows once the adapter normalises separators.
 */
const SENSITIVE_PATH_FRAGMENTS: readonly string[] = [
  '/.ssh/',
  '/.aws/',
  '/.gnupg/',
  '/.config/gcloud/',
  '/.docker/config.json',
  '/.kube/config',
];

/** Exact basenames that are sensitive wherever they appear. */
const SENSITIVE_BASENAMES: readonly string[] = [
  '.npmrc',
  '.env',
  '.netrc',
  'id_rsa',
  'id_ed25519',
  'credentials',
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

/** Normalise Windows separators and lowercase-insensitive comparison basis. */
function normalisePath(path: string): string {
  return path.replace(/\\/g, '/');
}

function basename(path: string): string {
  const normalised = normalisePath(path);
  const lastSlash = normalised.lastIndexOf('/');
  return lastSlash === -1 ? normalised : normalised.slice(lastSlash + 1);
}

/** True when a filesystem path points at something secret-bearing. */
export function isSensitivePath(path: string): boolean {
  const normalised = normalisePath(path);

  if (SENSITIVE_ABSOLUTE.includes(normalised)) {
    return true;
  }
  // Ensure a leading slash so fragment matching catches paths that begin at a
  // sensitive directory (e.g. a path that literally starts with ".ssh/").
  const padded = normalised.startsWith('/') ? normalised : `/${normalised}`;
  if (SENSITIVE_PATH_FRAGMENTS.some((fragment) => padded.includes(fragment))) {
    return true;
  }
  return SENSITIVE_BASENAMES.includes(basename(normalised));
}

/** True when an environment variable name looks like a secret. */
export function isSensitiveEnv(name: string): boolean {
  return STRONG_SECRET.test(name) || WEAK_SECRET.test(name);
}
