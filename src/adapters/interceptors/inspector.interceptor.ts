import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
  loadBuiltin,
} from './support.js';

const inspector = loadBuiltin('node:inspector');

/** `inspector.Session` methods that open a control channel into the process. */
const SESSION_METHODS = ['connect', 'connectToMainThread'] as const;

/**
 * Intercepts the `node:inspector` module — the built-in debugger, which doubles
 * as a backdoor primitive.
 *
 * `new inspector.Session().connect()` followed by `session.post('Runtime.evaluate',
 * { expression })` runs arbitrary code inside the process; `inspector.open(port,
 * host)` exposes a WebSocket that gives a remote client full debugger control —
 * arbitrary evaluation, heap inspection, and a live channel out. Both were
 * reproduced against enforce mode with a deny-by-default policy: the session
 * connected and evaluated code with nothing in the report.
 *
 * Recorded as `code.eval`: opening an inspector is dynamic code execution by
 * another name, and it is default-deny for the same reason `vm` is. No ordinary
 * dependency opens a debugger, so this is near-zero-false-positive, high-signal.
 * The detail names the entry point (`inspector.open`, `inspector.Session.connect`).
 *
 * `open` is patched at the module surface; the session is patched on
 * `Session.prototype`, so a package that constructs its own session (the usual
 * shape) is still caught. In enforce mode the connection/open throws before the
 * channel exists.
 */
export class InspectorInterceptor implements CapabilityInterceptor {
  readonly name = 'inspector';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = inspector as unknown as Record<string, unknown>;

    const openRestore = patchMethod(
      mod,
      'open',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const decision = report(record, 'code.eval', 'inspector.open');
          if (!decision.allow) {
            throw blockedError('opening the inspector', decision.reason);
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (openRestore) {
      restores.push(openRestore);
    }

    const proto = prototypeOf((inspector as unknown as { Session?: unknown }).Session);
    if (proto) {
      for (const key of SESSION_METHODS) {
        const restore = patchMethod(
          proto,
          key,
          (original) =>
            function (this: unknown, ...args: unknown[]): unknown {
              const decision = report(record, 'code.eval', `inspector.Session.${key}`);
              if (!decision.allow) {
                throw blockedError('connecting an inspector session', decision.reason);
              }
              return (original as (...a: unknown[]) => unknown).apply(this, args);
            },
        );
        if (restore) {
          restores.push(restore);
        }
      }
    }

    return restorer(restores);
  }
}
