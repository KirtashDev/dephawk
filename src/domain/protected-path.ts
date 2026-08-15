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

/**
 * The basenames dephawk's config file is auto-discovered under. Kept here so the
 * CLI's discovery and the tamper check share one list — a name added to one is
 * seen by the other.
 */
export const DEPHAWK_CONFIG_BASENAMES: readonly string[] = [
  'dephawk.config.js',
  'dephawk.config.mjs',
  'dephawk.config.cjs',
];

const CONFIG_BASENAME_SET: ReadonlySet<string> = new Set(DEPHAWK_CONFIG_BASENAMES);

/**
 * True when a path is one of dephawk's own config files, matched by basename.
 *
 * Unlike the sink/baseline (absolute paths known up front and passed in
 * {@link protectedPathAffectedBy}), the config is auto-discovered from the cwd,
 * so on a run with no config yet there is no absolute path to protect — and a
 * dependency could *plant* `dephawk.config.js` in the cwd, which the next run
 * would load as policy and use to allowlist the attacker everything. Matching by
 * basename refuses that write in the first place. Nothing legitimate writes
 * dephawk's config from inside a monitored process: `dephawk init` and hand
 * edits both happen from the un-monitored parent.
 */
export function isDephawkConfigPath(path: string): boolean {
  const normalised = path.replace(/\\/g, '/');
  const name = normalised.slice(normalised.lastIndexOf('/') + 1).toLowerCase();
  return CONFIG_BASENAME_SET.has(name);
}
