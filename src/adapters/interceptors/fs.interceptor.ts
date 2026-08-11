import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isPersistenceTarget, isSensitivePath } from '../../domain/sensitivity.js';
import { protectedPathAffectedBy } from '../../domain/protected-path.js';
import { packageOwningPath } from '../../domain/package-dir.js';
import type { Capability } from '../../domain/capability.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  loadBuiltin,
  patchMethod,
  report,
  restorer,
  type RecordFn,
} from './support.js';

const fs = loadBuiltin('node:fs') as Record<string, unknown> & {
  realpathSync?: ((p: string) => string) & { native?: (p: string) => string };
  promises?: Record<string, unknown>;
};

/** One path argument of an `fs` member, and what touching it amounts to. */
interface PathArgument {
  readonly index: number;
  readonly capability: Capability;
}

/** An `fs` member to patch, and which of its arguments name paths. */
interface FsMethod {
  readonly key: string;
  readonly paths: readonly PathArgument[];
}

const reads = (key: string): FsMethod => ({
  key,
  paths: [{ index: 0, capability: 'fs.read' }],
});

const writes = (key: string): FsMethod => ({
  key,
  paths: [{ index: 0, capability: 'fs.write' }],
});

/** `fs` members taking a single path. */
const SINGLE_PATH: readonly FsMethod[] = [
  reads('readFile'),
  reads('readFileSync'),
  reads('createReadStream'),
  reads('open'),
  reads('openSync'),
  // `openAsBlob('~/.ssh/id_rsa')` hands back a Blob whose `.text()`/`.stream()`
  // reads the file without ever calling a named read member — a quiet way in.
  reads('openAsBlob'),
  // Listing is reading: `readdir('~/.ssh')` names every key on the machine and
  // every host in `known_hosts` without opening one of them, which is exactly
  // the reconnaissance step that precedes the theft.
  reads('readdir'),
  reads('readdirSync'),
  reads('opendir'),
  reads('opendirSync'),
  // Same shape, one level down: a symlink's target is content. `~/.ssh/id_rsa`
  // often points at the real key elsewhere, and following it by hand is how you
  // read the key without ever naming its path.
  reads('readlink'),
  reads('readlinkSync'),
  // `glob('~/.ssh/*')` is `readdir` with a filter — same recon, newer API.
  reads('glob'),
  reads('globSync'),
  // Watching is reading over time: `watch('~/.aws')` reports every change to a
  // secret directory — a recon/exfil channel that never calls a read member.
  reads('watch'),
  reads('watchFile'),
  writes('writeFile'),
  writes('writeFileSync'),
  writes('appendFile'),
  writes('appendFileSync'),
  writes('createWriteStream'),
  // Destruction is a write: erasing a file changes it as surely as rewriting it,
  // and these are the members an attacker reaches for to remove evidence.
  writes('unlink'),
  writes('unlinkSync'),
  writes('rm'),
  writes('rmSync'),
  writes('rmdir'),
  writes('rmdirSync'),
  writes('truncate'),
  writes('truncateSync'),
];

/** `fs` members taking a source and a destination. */
const TWO_PATHS: readonly FsMethod[] = [
  // Renaming removes the original and creates the target: both are writes.
  {
    key: 'rename',
    paths: [
      { index: 0, capability: 'fs.write' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'renameSync',
    paths: [
      { index: 0, capability: 'fs.write' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  // Copying reads the source and writes the destination.
  {
    key: 'copyFile',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'copyFileSync',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  // `cp` is `copyFile`'s recursive successor, and the difference matters: one
  // call — `cp('~/.ssh', '/tmp/loot', { recursive: true })` — takes the entire
  // directory. It does not route through `copyFile`, so patching that one was
  // not enough.
  {
    key: 'cp',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'cpSync',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  // A hard link is a second name for the *same bytes*. `link('~/.ssh/id_rsa',
  // 'notes.txt')` then `readFileSync('notes.txt')` reads the key — and unlike a
  // symlink, the read-time `realpath` resolution cannot catch it: a hard link is
  // a co-equal directory entry, so `realpath('notes.txt')` is `notes.txt`, not
  // the key. The only place to see it is the moment the alias is made. The alias
  // is a full read/write handle to the source's inode, so the source counts as
  // *both* a read (leaking `~/.ssh/id_rsa`) and a write — the write matters for
  // the protected audit log: `link(sink, alias)` then `writeFileSync(alias)`
  // would otherwise truncate the log through a name the tamper check never sees.
  // The destination is a write too (the into-package takeover check applies).
  {
    key: 'link',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 0, capability: 'fs.write' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'linkSync',
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 0, capability: 'fs.write' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  // A symlink writes only its destination — planting one at a sensitive path
  // (`symlink('/tmp/attacker-key', '~/.ssh/authorized_keys')`, or a payload
  // inside another package) is a write with no read member behind it. Only the
  // destination (index 1) counts: the target (index 0) is a path the link merely
  // points at, not read here — reading *through* the link later is caught by the
  // read-time realpath resolution, and treating the target as a read would flag
  // the many legitimate symlinks a build creates into its own tree.
  {
    key: 'symlink',
    paths: [{ index: 1, capability: 'fs.write' }],
  },
  {
    key: 'symlinkSync',
    paths: [{ index: 1, capability: 'fs.write' }],
  },
];

const METHODS: readonly FsMethod[] = [...SINGLE_PATH, ...TWO_PATHS];

/** The subset `fs.promises` exposes, under the same names. */
const PROMISE_METHODS: readonly FsMethod[] = METHODS.filter(
  (method) => !method.key.endsWith('Sync') && !method.key.startsWith('create'),
);

export interface FsInterceptorOptions {
  /**
   * Paths belonging to dephawk itself, refused to everyone. See
   * {@link import('../../domain/protected-path.js')}. Passed here as well as to
   * the policy engine because the interceptor needs to know which mundane paths
   * are worth reporting at all.
   */
  readonly protectedPaths?: readonly string[];
}

/**
 * Intercepts filesystem access to *sensitive* paths (`~/.ssh`, `~/.aws`,
 * `.npmrc`, `.env`, `/etc/passwd`, …) and to dephawk's own protected paths.
 * Mundane paths pass through untouched with no stack capture, so the common
 * case (reading app/`node_modules` files) is not slowed. Covers the callback,
 * sync, stream, and `fs.promises` surfaces, including the reconnaissance members
 * (`readdir`, `opendir`, `readlink`, `glob`, `watch` — learning what a secret
 * directory holds, where a key really lives, or when it changes), the bulk ones (`cp` takes a whole tree in
 * one call) and the destructive ones (`unlink`, `rm`, `truncate`, `rename`) an
 * attacker uses to remove traces.
 *
 * Limitation: file-descriptor-based calls (`read(fd, …)`), `realpath` (called
 * constantly by module resolution, so it would report far more than it caught),
 * and native addons are not covered. ESM named imports
 * (`import { readFileSync } from 'node:fs'`) *are* — see {@link loadBuiltin} for
 * why the interceptor acquires `fs` through `require`.
 */
export class FsInterceptor implements CapabilityInterceptor {
  readonly name = 'fs';
  private readonly protectedPaths: readonly string[];

  constructor(options: FsInterceptorOptions = {}) {
    this.protectedPaths = options.protectedPaths ?? [];
  }

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    this.patchAll(fs as unknown as Record<string, unknown>, METHODS, record, restores);

    const promises = (fs as unknown as { promises?: Record<string, unknown> }).promises;
    if (promises !== undefined) {
      this.patchAll(promises, PROMISE_METHODS, record, restores);
    }

    return restorer(restores);
  }

  private patchAll(
    target: Record<string, unknown>,
    methods: readonly FsMethod[],
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    for (const method of methods) {
      const restore = patchMethod(
        target,
        method.key,
        (original) =>
          (...args: unknown[]): unknown => {
            for (const { index, capability } of method.paths) {
              for (const path of resolvePaths(args[index])) {
                this.check(record, capability, path);
              }
            }
            return original(...args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }
  }

  /** Report a path worth reporting, and throw when the call is refused. */
  private check(record: RecordFn, capability: Capability, path: string): void {
    const isProtected = protectedPathAffectedBy(path, this.protectedPaths) !== null;
    // A write into an installed package's directory is reported whatever the
    // path looks like: only the policy engine knows who is writing, and one
    // package writing into another's is a takeover of that package's identity.
    // See {@link import('../../domain/package-dir.js')}.
    const intoPackage = capability === 'fs.write' && packageOwningPath(path) !== null;
    // Writing a shell startup file is persistence, not a secret read — judged on
    // writes only, and lexically (no realpath needed for a basename match).
    const persistence = capability === 'fs.write' && isPersistenceTarget(path);

    let target = path;
    if (!isProtected && !intoPackage && !persistence && !isSensitivePath(path)) {
      // Lexically mundane — but `path.resolve` does not follow symlinks, and a
      // link can point anywhere. `readFileSync('notes.txt')` where that is a
      // link to `~/.ssh/id_rsa` used to read the key with no event at all.
      // Resolve and judge the real target instead.
      const real = realPathOf(path);
      if (real === null) {
        return; // genuinely mundane: no stack capture, no event
      }
      // The real target has to be judged by every rule the lexical path was, or
      // a symlink launders a write to the audit log (`writeFileSync(link)` where
      // `link` resolves to the protected sink) or to a shell rc just as it would
      // launder a read of a secret.
      const realProtected = protectedPathAffectedBy(real, this.protectedPaths) !== null;
      const realPersistence = capability === 'fs.write' && isPersistenceTarget(real);
      if (!realProtected && !realPersistence && !isSensitivePath(real)) {
        return; // genuinely mundane: no stack capture, no event
      }
      // Report where the bytes actually come from. This stays a bare path on
      // purpose: the policy engine matches `detail` against the sensitivity
      // rules and the per-package allowlists, so decorating it (`… (via …)`)
      // would break allowlisting and, worse, make the sensitivity test miss.
      target = real;
    }

    const decision = report(record, capability, target);
    if (!decision.allow) {
      throw blockedError(`${capability} of ${target}`, decision.reason);
    }
  }
}

/**
 * The real filesystem location `path` names, or null when it resolves to
 * itself, cannot be resolved, or does not exist.
 *
 * Taken from `fs` at module load so it is the genuine implementation rather
 * than one of this interceptor's own wrappers — `realpath` is not patched, but
 * relying on that from inside the patch would be a trap for later.
 *
 * Cost is why this is only reached for paths that already look mundane:
 * measured at ~14 µs a call (`realpathSync.native`) against ~2 µs for `lstat`.
 * That sounded prohibitive until it was measured against real workloads rather
 * than assumed: Node resolves modules through internal bindings, not the public
 * `fs` API, so this interceptor sees **hundreds** of calls where the syscall
 * count is millions — 637 for a real `npm ci`, 96 for a `tsup` build. Ten
 * milliseconds, not ten seconds.
 */
const nativeRealpath: ((p: string) => string) | undefined =
  typeof fs.realpathSync?.native === 'function'
    ? fs.realpathSync.native
    : typeof fs.realpathSync === 'function'
      ? fs.realpathSync
      : undefined;

function realPathOf(path: string): string | null {
  if (nativeRealpath === undefined) {
    return null;
  }
  try {
    const real = nativeRealpath(path);
    return real === path ? null : real;
  } catch {
    // Does not exist yet. A *write* still has to be judged: the leaf may be new
    // while the directory holding it is a link — `write('/tmp/out/key', …)`
    // where `/tmp/out` points at `~/.ssh`. Resolve the parent and rebuild.
  }
  try {
    const parent = dirname(path);
    const realParent = nativeRealpath(parent);
    return realParent === parent ? null : join(realParent, basename(path));
  } catch {
    return null; // neither exists, or permission denied: nothing to judge
  }
}

/**
 * Every path an argument names. Usually one — but `glob` takes a list of
 * patterns, and a list whose entries were never looked at would be a free pass.
 */
function resolvePaths(arg: unknown): string[] {
  if (Array.isArray(arg)) {
    return arg.flatMap((entry) => resolvePaths(entry));
  }
  const single = resolvePath(arg);
  return single === null ? [] : [single];
}

function resolvePath(arg: unknown): string | null {
  if (typeof arg === 'string') {
    return resolve(arg);
  }
  if (arg instanceof URL) {
    return arg.protocol === 'file:' ? fileURLToPath(arg) : null;
  }
  if (Buffer.isBuffer(arg)) {
    return resolve(arg.toString('utf8'));
  }
  return null; // file descriptor or unsupported argument
}
