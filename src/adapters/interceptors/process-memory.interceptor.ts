import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  loadBuiltin,
  patchMethod,
  report,
  restorer,
  type RecordFn,
} from './support.js';

/**
 * Intercepts the ways to dump the process's own memory or environment wholesale,
 * each of which hands over every in-memory secret without touching `fs` or
 * `process.env` — the direct dumps below, plus *arming* a deferred one
 * (`v8.setHeapSnapshotNearHeapLimit`, and the `process.report.*` config setters
 * that make Node write the full report on a signal or crash):
 *
 * - `process.report.getReport()` / `writeReport()` — Node's diagnostic report
 *   includes an `environmentVariables` map of *every* environment variable,
 *   secrets and all. `getReport()` returns it as an object, so it needs no file
 *   at all; the env-var Proxy never sees it. Reproduced: a dependency read
 *   `SECRET_TOKEN` out of the report under `--enforce` with a deny-by-default
 *   policy, invisible in the report.
 * - `v8.writeHeapSnapshot()` / `getHeapSnapshot()` — a heap snapshot contains
 *   every live string in the process, which is where decrypted secrets, tokens
 *   and keys sit after they have been read.
 *
 * Both are recorded as the `process.memory` capability and denied by default: a
 * dependency dumping the heap or the diagnostic report is doing something no
 * ordinary package needs, and it is the kind of move that launders a secret past
 * every other interceptor. In enforce mode the call throws before the dump is
 * produced.
 */
export class ProcessMemoryInterceptor implements CapabilityInterceptor {
  readonly name = 'process-memory';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    const report_ = (process as unknown as { report?: Record<string, unknown> }).report;
    if (report_ !== undefined && report_ !== null) {
      for (const key of ['getReport', 'writeReport'] as const) {
        this.patch(report_, key, `process.report.${key}`, record, restores);
      }
      // The report can also be *armed* to fire later: setting `reportOnSignal`
      // (plus `signal`/`directory`/`filename`), `reportOnUncaughtException`, or
      // `reportOnFatalError` makes Node dump the full diagnostic report — every
      // environment variable and the heap — with no further call from the
      // dependency. Arming it is the move; the setters are accessors, so they are
      // guarded directly rather than via `patch()`.
      for (const key of [
        'reportOnSignal',
        'reportOnUncaughtException',
        'reportOnFatalError',
        'signal',
        'directory',
        'filename',
      ] as const) {
        this.patchAccessorSetter(report_, key, `process.report.${key}`, record, restores);
      }
    }

    const v8 = loadBuiltin<Record<string, unknown>>('node:v8');
    // `queryObjects(Ctor)` (Node ≥22) returns every live instance of a
    // constructor — the same heap-secret disclosure as a snapshot, at finer
    // grain: hand it `Buffer` or a token class and read the secrets straight out.
    // `setHeapSnapshotNearHeapLimit(n)` arms a snapshot to be written to disk when
    // the heap nears its limit — a deferred dump of every live secret, and the one
    // v8 dump member that was missing here.
    for (const key of [
      'writeHeapSnapshot',
      'getHeapSnapshot',
      'queryObjects',
      'setHeapSnapshotNearHeapLimit',
    ] as const) {
      this.patch(v8, key, `v8.${key}`, record, restores);
    }

    return restorer(restores);
  }

  /**
   * Guard the *setter* of an accessor property so assigning to it reports
   * `process.memory` and is refused in enforce. Used for the `process.report.*`
   * config accessors, where the assignment — not a method call — is what arms a
   * later dump. The getter is preserved so reads are untouched.
   */
  private patchAccessorSetter(
    target: Record<string, unknown>,
    key: string,
    detail: string,
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (
      descriptor === undefined ||
      typeof descriptor.set !== 'function' ||
      descriptor.configurable !== true
    ) {
      return; // not a reconfigurable accessor on this runtime
    }
    const originalSet = descriptor.set;
    try {
      // Spread the original descriptor so its getter/flags carry over verbatim
      // (an explicit `get: undefined` trips `exactOptionalPropertyTypes`), and
      // override only the setter.
      Object.defineProperty(target, key, {
        ...descriptor,
        set(value: unknown): void {
          const decision = report(record, 'process.memory', detail);
          if (!decision.allow) {
            throw blockedError(`arming a memory dump via ${detail}`, decision.reason);
          }
          originalSet.call(this, value);
        },
      });
    } catch {
      return; // best effort
    }
    restores.push(() => {
      try {
        Object.defineProperty(target, key, descriptor);
      } catch {
        /* nothing we can do */
      }
    });
  }

  private patch(
    target: Record<string, unknown>,
    key: string,
    detail: string,
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    const restore = patchMethod(
      target,
      key,
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const decision = report(record, 'process.memory', detail);
          if (!decision.allow) {
            throw blockedError(`process memory dump via ${detail}`, decision.reason);
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }
}
