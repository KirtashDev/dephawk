import childProcess from 'node:child_process';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';
import {
  captureMonitoringEnv,
  restoreMonitoring,
  type MonitoringEnv,
} from './monitored-env.js';

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

export interface ChildProcessInterceptorOptions {
  /**
   * URL of dephawk's register entrypoint, so children can be re-attached even
   * when `--import` was passed on the command line rather than through
   * `NODE_OPTIONS`. Optional: with `dephawk run`/`guard` the flag is already in
   * `NODE_OPTIONS` and is picked up from there.
   */
  readonly registerUrl?: string;
  /** The environment to snapshot. Defaults to `process.env` at install time. */
  readonly env?: NodeJS.ProcessEnv;
}

/**
 * Intercepts child-process creation (`spawn`, `exec`, `fork`, and their sync
 * variants). Every spawn is recorded and, in enforce mode, blocked unless the
 * package opts in — this is the classic `curl … | sh` move.
 *
 * It also **re-attaches dephawk to every child it lets through**. Monitoring
 * spreads by inheritance, so a dependency could blind dephawk for a whole
 * subtree simply by not passing it on — deleting `NODE_OPTIONS` and `DEPHAWK_*`
 * from the environment it hands the child, or from `process.env` before
 * spawning with no environment at all. The spawn was recorded; everything the
 * child then did was not. See {@link import('./monitored-env.js')}.
 *
 * Re-attaching rather than refusing is deliberate: building a clean environment
 * for a child is ordinary, legitimate behaviour (reproducible builds do it),
 * and there is no way to tell it apart from an attempt to escape. Restoring
 * costs the honest caller nothing, and the report notes when it was needed.
 *
 * Limitation: only the `child_process` module surface is covered. Native code
 * that forks via libuv/posix_spawn directly is invisible to dephawk.
 */
export class ChildProcessInterceptor implements CapabilityInterceptor {
  readonly name = 'child_process';
  private readonly options: ChildProcessInterceptorOptions;

  constructor(options: ChildProcessInterceptorOptions = {}) {
    this.options = options;
  }

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = childProcess as unknown as Record<string, unknown>;

    // Snapshot now: install runs before any dependency has had a chance to edit
    // the environment, so this is what dephawk was really started with.
    const monitoring = captureMonitoringEnv(
      this.options.env ?? process.env,
      this.options.registerUrl,
    );

    for (const key of SPAWN_METHODS) {
      const restore = patchMethod(
        mod,
        key,
        (original) =>
          (...args: unknown[]): unknown => {
            const restored = reattach(args, monitoring);
            const detail = describeSpawn(args, restored);

            const decision = report(record, 'process.spawn', detail);
            if (!decision.allow) {
              throw blockedError(`spawn of ${detail}`, decision.reason);
            }
            return original(...args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}

/**
 * Put monitoring back into the environment the child will get, mutating `args`
 * in place. Returns the names that had to be restored.
 *
 * When the caller supplied an environment we edit their copy. When it did not,
 * the child inherits `process.env`, so we repair that instead — deliberately
 * rather than materialising a copy, both to leave the caller's semantics alone
 * and to avoid reading every variable through the env interceptor's proxy,
 * which would report a secret read on every spawn.
 */
function reattach(args: unknown[], monitoring: MonitoringEnv): readonly string[] {
  const optionsIndex = findOptionsIndex(args);
  const options =
    optionsIndex === -1 ? undefined : (args[optionsIndex] as Record<string, unknown>);
  const childEnv = options?.['env'];

  if (childEnv === undefined || childEnv === null) {
    const { env, restored } = restoreMonitoring(process.env, monitoring);
    for (const name of restored) {
      process.env[name] = env[name];
    }
    return restored;
  }

  const { env, restored } = restoreMonitoring(childEnv as NodeJS.ProcessEnv, monitoring);
  if (restored.length > 0 && options !== undefined) {
    args[optionsIndex] = { ...options, env };
  }
  return restored;
}

/**
 * Index of the options object, or -1.
 *
 * Every entrypoint takes it last before an optional callback, after a command
 * and optional arguments — and options is the only plain object among those, so
 * scanning for one is more robust than a table of per-method positions.
 */
function findOptionsIndex(args: readonly unknown[]): number {
  const end =
    args.length > 0 && typeof args[args.length - 1] === 'function'
      ? args.length - 1
      : args.length;

  for (let index = end - 1; index >= 1; index--) {
    const candidate = args[index];
    if (
      typeof candidate === 'object' &&
      candidate !== null &&
      !Array.isArray(candidate)
    ) {
      return index;
    }
  }
  return -1;
}

function describeSpawn(args: readonly unknown[], restored: readonly string[]): string {
  const command = typeof args[0] === 'string' ? args[0] : String(args[0]);
  const list = Array.isArray(args[1])
    ? args[1].filter((arg): arg is string => typeof arg === 'string')
    : [];
  const spawn = list.length > 0 ? `${command} ${list.join(' ')}` : command;

  return restored.length === 0
    ? spawn
    : `${spawn} [dephawk re-attached: ${restored.join(', ')}]`;
}
