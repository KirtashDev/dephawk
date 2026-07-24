import childProcess from 'node:child_process';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  report,
  restorer,
  type RecordFn,
} from './support.js';

/** All the child_process entrypoints that start a process. */
const SPAWN_METHODS = [
  'spawn',
  'spawnSync',
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'fork',
] as const;

/**
 * Intercepts child-process creation (`spawn`, `exec`, `fork`, and their sync
 * variants). Every spawn is recorded and, in enforce mode, blocked unless the
 * package opts in — this is the classic `curl … | sh` move.
 *
 * Limitation: only the `child_process` module surface is covered. Native code
 * that forks via libuv/posix_spawn directly is invisible to dephawk.
 */
export class ChildProcessInterceptor implements CapabilityInterceptor {
  readonly name = 'child_process';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = childProcess as unknown as Record<string, unknown>;

    for (const key of SPAWN_METHODS) {
      const restore = patchMethod(mod, key, (original) => (...args: unknown[]): unknown => {
        const detail = describeSpawn(args);
        const decision = report(record, 'process.spawn', detail);
        if (!decision.allow) {
          throw blockedError(`spawn of ${detail}`, decision.reason);
        }
        return original(...args);
      });
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}

function describeSpawn(args: readonly unknown[]): string {
  const command = typeof args[0] === 'string' ? args[0] : String(args[0]);
  const list = Array.isArray(args[1])
    ? args[1].filter((arg): arg is string => typeof arg === 'string')
    : [];
  return list.length > 0 ? `${command} ${list.join(' ')}` : command;
}
