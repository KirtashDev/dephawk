import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, report, restorer, type RecordFn, loadBuiltin } from './support.js';

const workerThreads = loadBuiltin('node:worker_threads');

import {
  captureMonitoringEnv,
  restoreWorkerOptions,
  type MonitoringEnv,
} from './monitored-env.js';

export interface WorkerInterceptorOptions {
  /** Environment to snapshot monitoring from. Defaults to `process.env`. */
  readonly env?: NodeJS.ProcessEnv;
  /**
   * URL of dephawk's register entrypoint, for the
   * `node --import dephawk/register` form where the flag is on the command line
   * and never appears in `NODE_OPTIONS`.
   */
  readonly registerUrl?: string;
}

/**
 * Intercepts worker-thread creation (`new worker_threads.Worker(...)`).
 * Recorded as `process.spawn` — a worker is another way to run code the caller
 * controls, and it doubles as an *evasion vector*: work moved onto a worker
 * runs on a fresh call stack, so a package can launder a sensitive action past
 * dephawk's stack-based attribution. Gated by the same `spawn` policy as
 * `child_process`.
 *
 * The detail is the worker script path, or `<inline eval>` when the worker is
 * constructed with `{ eval: true }` (source passed as a string).
 *
 * **Monitoring is re-attached**, the same decision as
 * {@link import('./child-process.interceptor.js') child processes} and for the
 * same reason: a worker inherits `process.execArgv` and the environment, and
 * anything inherited can be declined. `new Worker(f, { execArgv: [] })` ran
 * completely unmonitored — the worker was recorded, everything it then did was
 * not — and `{ env: {} }` did the same by dropping `NODE_OPTIONS`. Both are put
 * back, and the report line says so. A caller who passes neither inherits both
 * and needs nothing.
 *
 * Implementation note: `Worker` is a class, so it is wrapped with a subclass
 * rather than the plain method patch. The decision is taken *before* `super()`
 * (no `this` is touched first), so a denied worker throws before the underlying
 * thread is ever created.
 */
export class WorkerInterceptor implements CapabilityInterceptor {
  readonly name = 'worker';
  private readonly options: WorkerInterceptorOptions;

  constructor(options: WorkerInterceptorOptions = {}) {
    this.options = options;
  }

  install(record: RecordFn): Disposable {
    const mod = workerThreads as unknown as Record<string, unknown>;
    const Original = mod['Worker'];
    if (typeof Original !== 'function') {
      return restorer([]);
    }

    const OriginalWorker = Original as unknown as {
      new (...args: unknown[]): object;
    };

    // Snapshot before any dependency has run, as the child-process interceptor
    // does: this is what dephawk was started with.
    const monitoring = captureMonitoringEnv(
      this.options.env ?? process.env,
      this.options.registerUrl,
    );

    class PatchedWorker extends OriginalWorker {
      constructor(...args: unknown[]) {
        const restored = reattach(args, monitoring);
        const detail = describeWorker(args, restored);
        const decision = report(record, 'process.spawn', detail);
        if (!decision.allow) {
          throw blockedError(`worker thread ${detail}`, decision.reason);
        }
        super(...args);
      }
    }

    // Preserve static members (e.g. any future statics) and the visible name.
    Object.defineProperty(PatchedWorker, 'name', { value: 'Worker', configurable: true });

    define(mod, 'Worker', PatchedWorker);
    return restorer([() => define(mod, 'Worker', Original)]);
  }
}

/**
 * Guarantee monitoring in the options the worker will start with, replacing the
 * options object in `args` rather than mutating the caller's. Returns what had to
 * be put back — nothing when the caller passed no options, because then the
 * worker inherits `process.execArgv` and the parent environment, which already
 * carry monitoring. The merge itself is a pure transform in `monitored-env.ts`.
 */
function reattach(args: unknown[], monitoring: MonitoringEnv): readonly string[] {
  const options = args[1];
  if (!isObject(options)) {
    return [];
  }
  const { options: patched, restored } = restoreWorkerOptions(
    options,
    monitoring,
    process.execArgv,
  );
  if (restored.length > 0) {
    args[1] = patched;
  }
  return restored;
}

function describeWorker(args: readonly unknown[], restored: readonly string[]): string {
  const worker = describeTarget(args);
  return restored.length === 0
    ? worker
    : `${worker} [dephawk re-attached: ${restored.join(', ')}]`;
}

function describeTarget(args: readonly unknown[]): string {
  const filename = args[0];
  const options = args[1];
  if (isObject(options) && options['eval'] === true) {
    return '<inline eval>';
  }
  if (typeof filename === 'string') {
    return filename;
  }
  if (filename instanceof URL) {
    return filename.href;
  }
  return 'unknown';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function define(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    configurable: true,
    enumerable: Object.prototype.propertyIsEnumerable.call(target, key),
  });
}
