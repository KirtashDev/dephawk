/**
 * Paths that belong to dephawk itself rather than to the monitored program.
 *
 * Today that means one thing: the shared JSONL sink `dephawk guard` uses to
 * aggregate events across every process an install spawns. Its location travels
 * to each monitored process in `DEPHAWK_SINK`, so the monitored code can read it
 * — and a malicious lifecycle script only had to truncate the file to erase
 * every capability its neighbours had already recorded. The audit log is not
 * part of the program's own data, and nothing has a legitimate reason to write
 * to it, so access is refused outright rather than run through user policy.
 *
 * Pure string comparison: the adapter resolves paths, the domain only matches.
 */

/**
 * The protected path this access would affect, or null.
 *
 * Matches the file itself and any ancestor directory, so removing the enclosing
 * temp directory counts as tampering just as much as truncating the file.
 */
export function protectedPathAffectedBy(
  path: string,
  protectedPaths: readonly string[],
): string | null {
  for (const candidate of protectedPaths) {
    if (path === candidate || candidate.startsWith(`${path}/`)) {
      return candidate;
    }
  }
  return null;
}
