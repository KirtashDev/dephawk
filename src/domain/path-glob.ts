/**
 * Pure path prefix matching for filesystem allowlists.
 *
 * A pattern matches a path when:
 * - it ends with `*` and the path starts with the text before the `*`, or
 * - it equals the path exactly, or
 * - it names a directory that contains the path (`/a/b` matches `/a/b/c`).
 *
 * Paths are compared with forward slashes; the adapter normalises separators.
 */

function normalise(path: string): string {
  return path.replace(/\\/g, '/');
}

export function pathMatches(path: string, pattern: string): boolean {
  const p = normalise(path);
  const pat = normalise(pattern);

  if (pat.endsWith('*')) {
    return p.startsWith(pat.slice(0, -1));
  }
  if (p === pat) {
    return true;
  }
  const asDir = pat.endsWith('/') ? pat : `${pat}/`;
  return p.startsWith(asDir);
}

export function pathMatchesAny(path: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => pathMatches(path, pattern));
}
