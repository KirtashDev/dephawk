import workerThreads from 'node:worker_threads';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, report, restorer, type RecordFn } from './support.js';

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
 * Implementation note: `Worker` is a class, so it is wrapped with a subclass
 * rather than the plain method patch. The decision is taken *before* `super()`
 * (no `this` is touched first), so a denied worker throws before the underlying
 * thread is ever created.
 */
export class WorkerInterceptor implements CapabilityInterceptor {
  readonly name = 'worker';

  install(record: RecordFn): Disposable {
    const mod = workerThreads as unknown as Record<string, unknown>;
    const Original = mod['Worker'];
    if (typeof Original !== 'function') {
      return restorer([]);
    }

    const OriginalWorker = Original as unknown as {
      new (...args: unknown[]): object;
    };

    class PatchedWorker extends OriginalWorker {
      constructor(...args: unknown[]) {
        const detail = describeWorker(args);
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

function describeWorker(args: readonly unknown[]): string {
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
