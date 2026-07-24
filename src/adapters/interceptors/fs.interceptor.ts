import fs from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSensitivePath } from '../../domain/sensitivity.js';
import type { Capability } from '../../domain/capability.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';

const READ_METHODS = [
  'readFile',
  'readFileSync',
  'createReadStream',
  'open',
  'openSync',
] as const;

const WRITE_METHODS = [
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'createWriteStream',
] as const;

/**
 * Intercepts filesystem access to *sensitive* paths (`~/.ssh`, `~/.aws`,
 * `.npmrc`, `.env`, `/etc/passwd`, …). Mundane paths pass through untouched
 * with no stack capture, so the common case (reading app/`node_modules` files)
 * is not slowed. Covers the callback, sync, stream, and `fs.promises` surfaces.
 *
 * Limitation: file-descriptor-based calls (`read(fd, …)`), native addons, and
 * named bindings captured before install are not covered.
 */
export class FsInterceptor implements CapabilityInterceptor {
  readonly name = 'fs';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = fs as unknown as Record<string, unknown>;

    this.patchGroup(mod, READ_METHODS, 'fs.read', record, restores);
    this.patchGroup(mod, WRITE_METHODS, 'fs.write', record, restores);

    const promises = (fs as unknown as { promises?: Record<string, unknown> }).promises;
    if (promises !== undefined) {
      this.patchGroup(promises, ['readFile', 'open'], 'fs.read', record, restores);
      this.patchGroup(
        promises,
        ['writeFile', 'appendFile'],
        'fs.write',
        record,
        restores,
      );
    }

    return restorer(restores);
  }

  private patchGroup(
    target: Record<string, unknown>,
    keys: readonly string[],
    capability: Capability,
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    for (const key of keys) {
      const restore = patchMethod(
        target,
        key,
        (original) =>
          (...args: unknown[]): unknown => {
            const path = resolvePath(args[0]);
            if (path !== null && isSensitivePath(path)) {
              const decision = report(record, capability, path);
              if (!decision.allow) {
                throw blockedError(`${capability} of ${path}`, decision.reason);
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
