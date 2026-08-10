/**
 * Which installed package a path belongs to.
 *
 * Pure string work, like the rest of the domain: no filesystem, no Node types.
 *
 * This exists for one rule. A dependency that writes into *another* package's
 * directory takes over that package's identity: attribution is done by walking
 * the stack for the first `node_modules/<name>` frame, so code planted in
 * `node_modules/innocent/` genuinely runs as `innocent` and inherits whatever
 * the policy grants it. Reproduced against `--enforce` with a deny-by-default
 * policy: the payload was written, `require`d, read a secret, and the report
 * named `innocent` — the attacker appeared nowhere.
 *
 * Nothing about that is forgery, which is why it cannot be fixed in the
 * attributor: the code really is in that directory. The write is the moment to
 * catch it.
 */

const NODE_MODULES = 'node_modules/';

/**
 * The package owning `path`, or null when it is not inside one.
 *
 * The *last* `node_modules/` segment wins, so a nested install
 * (`a/node_modules/b/index.js`) belongs to `b` — the same rule the stack
 * attributor uses, so the owner here and the culprit there are comparable.
 * Scoped names (`@scope/name`) are kept whole.
 */
export function packageOwningPath(path: string): string | null {
  const normalised = path.replace(/\\/g, '/');
  const index = normalised.lastIndexOf(NODE_MODULES);
  if (index === -1) {
    return null;
  }
  const segments = normalised.slice(index + NODE_MODULES.length).split('/');
  const first = segments[0];
  if (first === undefined || first.length === 0) {
    return null;
  }
  if (!first.startsWith('@')) {
    // A file directly inside `node_modules/` (not in a package) has no owner:
    // `node_modules/.package-lock.json` belongs to the installer, not a package.
    return segments.length > 1 ? first : null;
  }
  const second = segments[1];
  if (second === undefined || second.length === 0) {
    return null; // malformed scoped path
  }
  return segments.length > 2 ? `${first}/${second}` : null;
}

/**
 * Whether `writer` writing into a file owned by `owner` is one package reaching
 * into another's directory.
 *
 * A package writing inside its own directory is ordinary — caches, compiled
 * output, downloaded binaries — and stays allowed. Only crossing into someone
 * else's is the takeover.
 */
export function isCrossPackageWrite(
  writer: string | null,
  owner: string | null,
): boolean {
  return owner !== null && writer !== null && writer !== owner;
}
