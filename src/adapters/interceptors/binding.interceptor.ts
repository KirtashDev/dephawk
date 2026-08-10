import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';

/** The internal-binding accessors a package can reach from userland. */
const BINDING_METHODS = ['binding', '_linkedBinding'] as const;

/**
 * Intercepts `process.binding` and `process._linkedBinding` — the doors into
 * Node's internal C++ bindings.
 *
 * This is the master escape hatch. `process.binding('fs')` hands back the raw
 * filesystem binding (`readFileUtf8`, `open`, `read`); `process.binding('spawn_sync')`,
 * `process.binding('tcp_wrap')`, `process.binding('cares_wrap')` do the same for
 * spawning, sockets, and DNS. None of them route through the `node:*` modules
 * the other interceptors patch, so a single `process.binding('fs').readFileUtf8`
 * reads any file with the report showing nothing — reproduced against enforce
 * mode with a deny-by-default policy before this was written.
 *
 * It is recorded as `process.native`: like a native addon, a binding grabs raw
 * runtime power that sits outside the JavaScript surface dephawk observes, and
 * it is default-deny for exactly the same reason. The detail is the requested
 * binding name (`fs`, `spawn_sync`, …). `process.binding` is pending-deprecated
 * (DEP0111) but fully functional through at least Node 22, and nothing a normal
 * dependency does needs it — so a dependency reaching for it is a red flag on
 * its own, whichever binding it asks for.
 *
 * Limitation: the truly-internal `internalBinding` is not reachable from
 * userland without the flags/frames dephawk would already catch, so it is not
 * covered here.
 */
export class BindingInterceptor implements CapabilityInterceptor {
  readonly name = 'binding';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const target = process as unknown as Record<string, unknown>;

    for (const key of BINDING_METHODS) {
      const restore = patchMethod(
        target,
        key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            const name = typeof args[0] === 'string' ? args[0] : 'unknown';
            const decision = report(record, 'process.native', `process.${key}(${name})`);
            if (!decision.allow) {
              throw blockedError(
                `internal binding access process.${key}(${name})`,
                decision.reason,
              );
            }
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}
