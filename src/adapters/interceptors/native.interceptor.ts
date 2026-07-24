import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';

/**
 * Intercepts native-addon loading via `process.dlopen` — the single primitive
 * every `require('*.node')` and every prebuilt-binary package funnels through
 * to map compiled code into the process.
 *
 * This is the highest-signal capability dephawk watches: a native addon runs
 * outside the JavaScript sandbox and can bypass *all* of dephawk's other
 * interceptors (its own `fs`/`net`/`spawn` never touch the patched built-ins).
 * A dependency you did not expect to be native loading a `.node` file is a red
 * flag; legitimately-native packages (`bcrypt`, `sharp`, …) opt in with
 * `{ native: true }`.
 *
 * Recorded as `process.native` with the addon path as the detail. In enforce
 * mode a disallowed load throws before the binary is mapped.
 */
export class NativeAddonInterceptor implements CapabilityInterceptor {
  readonly name = 'native';

  install(record: RecordFn): Disposable {
    const restore = patchMethod(
      process as unknown as Record<string, unknown>,
      'dlopen',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const detail = typeof args[1] === 'string' ? args[1] : 'unknown';
          const decision = report(record, 'process.native', detail);
          if (!decision.allow) {
            throw blockedError(`native addon load of ${detail}`, decision.reason);
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );

    return restorer(restore ? [restore] : []);
  }
}
