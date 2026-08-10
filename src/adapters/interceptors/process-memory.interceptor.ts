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
 * Intercepts the two ways to dump the process's own memory or environment
 * wholesale, each of which hands over every in-memory secret without touching
 * `fs` or `process.env`:
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
    }

    const v8 = loadBuiltin<Record<string, unknown>>('node:v8');
    for (const key of ['writeHeapSnapshot', 'getHeapSnapshot'] as const) {
      this.patch(v8, key, `v8.${key}`, record, restores);
    }

    return restorer(restores);
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
