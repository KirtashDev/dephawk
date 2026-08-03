import fs from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSensitivePath } from '../../domain/sensitivity.js';
import { protectedPathAffectedBy } from '../../domain/protected-path.js';
import type { Capability } from '../../domain/capability.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';

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
 * sync, stream, and `fs.promises` surfaces, including the destructive members
 * (`unlink`, `rm`, `truncate`, `rename`) an attacker uses to remove traces.
 *
 * Limitation: file-descriptor-based calls (`read(fd, …)`), native addons, and
 * named bindings captured before install are not covered.
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
              this.check(record, capability, resolvePath(args[index]));
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
  private check(record: RecordFn, capability: Capability, path: string | null): void {
    if (path === null) {
      return;
    }
    const isProtected = protectedPathAffectedBy(path, this.protectedPaths) !== null;
    if (!isProtected && !isSensitivePath(path)) {
      return; // mundane: no stack capture, no event
    }
    const decision = report(record, capability, path);
    if (!decision.allow) {
      throw blockedError(`${capability} of ${path}`, decision.reason);
    }
  }
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
