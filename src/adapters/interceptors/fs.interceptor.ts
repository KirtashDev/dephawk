import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isPersistenceTarget, isSensitivePath } from '../../domain/sensitivity.js';
import {
  isCiWorkflowPath,
  isEditorHookPath,
  isGitHookPath,
} from '../../domain/threat.js';
import {
  isDephawkConfigPath,
  protectedPathAffectedBy,
} from '../../domain/protected-path.js';
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

/** Node's own path-type check: true for a Buffer *and* any plain Uint8Array. */
const isUint8Array = (
  loadBuiltin('node:util') as { types: { isUint8Array(value: unknown): boolean } }
).types.isUint8Array;

/** One path argument of an `fs` member, and what touching it amounts to. */
interface PathArgument {
  readonly index: number;
  readonly capability: Capability;
}

/** An `fs` member to patch, and which of its arguments name paths. */
interface FsMethod {
  readonly key: string;
  readonly paths: readonly PathArgument[];
  /**
   * The argument index carrying open flags, if this is an `open`-family member.
   * When set, the path at index 0 is judged by the *flags* — a read when the
   * file is opened for reading, a write when opened for writing — instead of the
   * static {@link paths} list. Without this, `open(path, 'w')` was classed as a
   * read, so a write to a persistence/sensitive path through the returned
   * descriptor (`fs.writeSync(fd, …)`, which is fd-based and unpatched) slipped
   * past every write-side rule.
   */
  readonly flagsIndex?: number;
  /**
   * A member that copies/moves a whole directory tree (`cp`/`rename`). Its leaves
   * are created by Node's internal copy, invisible to every per-member patch, so
   * when the source is a directory the wrapper enumerates them and judges each
   * destination leaf as an `fs.write`.
   */
  readonly treeCopy?: boolean;
}

const reads = (key: string): FsMethod => ({
  key,
  paths: [{ index: 0, capability: 'fs.read' }],
});

const writes = (key: string): FsMethod => ({
  key,
  paths: [{ index: 0, capability: 'fs.write' }],
});

/** `open`/`openSync`/`promises.open` — path at index 0, flags at index 1. */
const opens = (key: string): FsMethod => ({
  key,
  paths: [{ index: 0, capability: 'fs.read' }],
  flagsIndex: 1,
});

/**
 * Whether an open-flags argument requests read / write access. Handles both the
 * string forms (`'r'`, `'w'`, `'a'`, `'r+'`, `'as'`, …) and the numeric bitmask
 * (`O_RDONLY`/`O_WRONLY`/`O_RDWR` in the low two bits). A missing/unknown flag
 * defaults to `'r'` — read-only — which is Node's own default.
 */
function accessMode(flags: unknown): { read: boolean; write: boolean } {
  if (typeof flags === 'number') {
    const access = flags & 0o3; // O_ACCMODE
    return {
      read: access === 0 /* O_RDONLY */ || access === 2 /* O_RDWR */,
      write: access === 1 /* O_WRONLY */ || access === 2 /* O_RDWR */,
    };
  }
  if (typeof flags === 'string') {
    return { read: /[r+]/.test(flags), write: /[wa+]/.test(flags) };
  }
  return { read: true, write: false };
}

/** `fs` members taking a single path. */
const SINGLE_PATH: readonly FsMethod[] = [
  reads('readFile'),
  reads('readFileSync'),
  reads('createReadStream'),
  opens('open'),
  opens('openSync'),
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
  // Changing a file's mode, owner, or timestamps is a write to it: loosening the
  // permissions on `~/.ssh/id_rsa` (a read-enabler with no read of its own),
  // marking a dropped payload executable, or back-dating a tampered file to hide
  // it. The `f`-variants take a descriptor, not a path, so they are out of scope
  // like the rest of the fd-based surface.
  writes('chmod'),
  writes('chmodSync'),
  writes('lchmod'),
  writes('lchmodSync'),
  writes('chown'),
  writes('chownSync'),
  writes('lchown'),
  writes('lchownSync'),
  writes('utimes'),
  writes('utimesSync'),
  writes('lutimes'),
  writes('lutimesSync'),
];

/** `fs` members taking a source and a destination. */
const TWO_PATHS: readonly FsMethod[] = [
  // Renaming removes the original and creates the target: both are writes.
  {
    key: 'rename',
    treeCopy: true,
    paths: [
      { index: 0, capability: 'fs.write' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'renameSync',
    treeCopy: true,
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
    treeCopy: true,
    paths: [
      { index: 0, capability: 'fs.read' },
      { index: 1, capability: 'fs.write' },
    ],
  },
  {
    key: 'cpSync',
    treeCopy: true,
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
            if (method.flagsIndex !== undefined) {
              // `open`-family: judge the path by the flags, not a fixed role. A
              // write-intent open runs the full write-side gate (persistence,
              // into-package, sensitive write); a read-intent open runs the read
              // gate. `r+`/`w+`/`a+` are both, so both fire.
              const mode = accessMode(args[method.flagsIndex]);
              for (const path of resolvePaths(args[0])) {
                if (mode.read) {
                  this.check(record, 'fs.read', path);
                }
                if (mode.write) {
                  this.check(record, 'fs.write', path);
                }
              }
            } else {
              for (const { index, capability } of method.paths) {
                for (const path of resolvePaths(args[index])) {
                  this.check(record, capability, path);
                }
              }
            }
            if (method.treeCopy) {
              this.checkTreeCopy(record, method, args);
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
    // Writing a shell startup file, or a CI workflow (`.github/workflows/*.yml` —
    // the Shai-Hulud worm's self-persistence move), is a write-side attack: judged
    // on writes only, lexically. See {@link import('../../domain/threat.js')}.
    const persistence =
      capability === 'fs.write' &&
      (isPersistenceTarget(path) ||
        isCiWorkflowPath(path) ||
        isGitHookPath(path) ||
        isEditorHookPath(path));
    // Planting dephawk's own config for the next run to load as policy is a
    // self-defense attack, matched by basename (its absolute path is unknown on a
    // no-config run). See {@link import('../../domain/protected-path.js')}.
    const configTamper = capability === 'fs.write' && isDephawkConfigPath(path);

    let target = path;
    if (
      !isProtected &&
      !intoPackage &&
      !persistence &&
      !configTamper &&
      !isSensitivePath(path)
    ) {
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
      const realPersistence =
        capability === 'fs.write' &&
        (isPersistenceTarget(real) ||
          isCiWorkflowPath(real) ||
          isGitHookPath(real) ||
          isEditorHookPath(real));
      const realConfigTamper = capability === 'fs.write' && isDephawkConfigPath(real);
      if (
        !realProtected &&
        !realPersistence &&
        !realConfigTamper &&
        !isSensitivePath(real)
      ) {
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

  /**
   * For a directory `cp`/`rename`, judge each destination leaf the recursive copy
   * will create as an `fs.write`. The leaves never pass through a patched member
   * (Node copies them internally), so without this a payload staged in a mundane
   * directory and copied onto `.github`, `.git/hooks`, `node_modules/<pkg>` or the
   * repo root lands unseen and unblocked.
   */
  private checkTreeCopy(
    record: RecordFn,
    method: FsMethod,
    args: readonly unknown[],
  ): void {
    const source = resolvePath(args[0]);
    const destination = resolvePath(args[1]);
    if (source === null || destination === null || !isDirectory(source)) {
      return; // a file source is already covered by the per-path fs.write check
    }
    // `cp` needs `{ recursive: true }` to copy a directory; a directory `rename`
    // always moves the whole tree.
    const isRename = method.key.startsWith('rename');
    if (!isRename && !isRecursiveCp(args)) {
      return;
    }
    for (const rel of relativeLeaves(source)) {
      this.checkWriteLeaf(record, join(destination, rel));
    }
  }

  /**
   * The `fs.write` gate for a leaf a recursive copy will create — the lexical
   * checks only. `realPathOf` is deliberately skipped: the leaf does not exist
   * yet (it is about to be created), so there is no symlink to resolve, and
   * skipping it keeps a large legitimate copy fast (mundane leaves return after a
   * few string tests, with no syscall).
   */
  private checkWriteLeaf(record: RecordFn, path: string): void {
    const isProtected = protectedPathAffectedBy(path, this.protectedPaths) !== null;
    const intoPackage = packageOwningPath(path) !== null;
    const persistence =
      isPersistenceTarget(path) ||
      isCiWorkflowPath(path) ||
      isGitHookPath(path) ||
      isEditorHookPath(path);
    const configTamper = isDephawkConfigPath(path);
    if (
      !isProtected &&
      !intoPackage &&
      !persistence &&
      !configTamper &&
      !isSensitivePath(path)
    ) {
      return; // mundane leaf
    }
    const decision = report(record, 'fs.write', path);
    if (!decision.allow) {
      throw blockedError(`fs.write of ${path}`, decision.reason);
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

/**
 * `readdir`/`lstat` captured at module load — the genuine implementations, before
 * `install()` patches `readdirSync`. Used to walk a recursive-copy source tree
 * *without* re-entering this interceptor. `cp`/`rename` of a directory create
 * every leaf through Node's internal C++ copy, calling no patched `fs` member, so
 * the leaves must be enumerated here or a whole class of writes (a planted
 * `.github/workflows/x.yml`, `.git/hooks/pre-commit`, `node_modules/victim/…`, or
 * `dephawk.config.js`) lands with no event and no block.
 */
type Dirent = { name: string; isDirectory(): boolean; isSymbolicLink(): boolean };
const nativeReaddir: ((p: string, opts: object) => Dirent[]) | undefined =
  typeof fs['readdirSync'] === 'function'
    ? (fs['readdirSync'] as (p: string, opts: object) => Dirent[])
    : undefined;
const nativeLstat: ((p: string) => { isDirectory(): boolean }) | undefined =
  typeof fs['lstatSync'] === 'function'
    ? (fs['lstatSync'] as (p: string) => { isDirectory(): boolean })
    : undefined;

/** True when `path` is a directory on disk (via the uninstrumented `lstat`). */
function isDirectory(path: string): boolean {
  if (nativeLstat === undefined) {
    return false;
  }
  try {
    return nativeLstat(path).isDirectory();
  } catch {
    return false;
  }
}

/** A recursive-copy `cp`/`cpSync` call (dir sources need `{ recursive: true }`). */
function isRecursiveCp(args: readonly unknown[]): boolean {
  const options = args[2];
  return (
    typeof options === 'object' &&
    options !== null &&
    (options as { recursive?: unknown }).recursive === true
  );
}

/** A cap so a genuine large recursive copy cannot turn the walk into a hang. */
const MAX_TREE_LEAVES = 20_000;

/**
 * Yield every file/symlink leaf under `root` as a path relative to it, using the
 * uninstrumented `readdir`/`lstat`. Directory symlinks are not followed (a leaf,
 * not descended) so a cycle cannot trap the walk.
 */
function* relativeLeaves(root: string): Iterable<string> {
  if (nativeReaddir === undefined) {
    return;
  }
  const stack: string[] = [''];
  let seen = 0;
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    const abs = rel === '' ? root : join(root, rel);
    let entries: Dirent[];
    try {
      entries = nativeReaddir(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const childRel = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        stack.push(childRel);
      } else {
        yield childRel;
        if (++seen >= MAX_TREE_LEAVES) {
          return;
        }
      }
    }
  }
}

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
  // Node accepts any Uint8Array as a path, not only a Buffer — and a plain
  // `new TextEncoder().encode('/etc/passwd')` is NOT a Buffer, so it used to slip
  // past this decoder entirely: `resolvePaths` returned `[]`, `check()` never
  // ran, and the file was read or written with no event. Decode it the way Node
  // does. `isUint8Array` (util.types) also matches a Buffer and works across
  // realms, so the old `Buffer.isBuffer` branch is subsumed.
  if (isUint8Array(arg)) {
    const view = arg as Uint8Array;
    const bytes = Buffer.isBuffer(view)
      ? view
      : Buffer.from(view.buffer, view.byteOffset, view.byteLength);
    return resolve(bytes.toString('utf8'));
  }
  return null; // file descriptor or unsupported argument
}
