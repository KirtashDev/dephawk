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
 * Env var name pattern for secrets. Deliberately broad — false positives here
 * are cheap (an extra line in the report), false negatives are the failure we
 * actually care about.
 */
const SECRET_ENV_PATTERN =
  /(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|SESSION|COOKIE|API[_-]?KEY|ACCESS)/i;

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
  return SECRET_ENV_PATTERN.test(name);
}
