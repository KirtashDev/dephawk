import { isSensitiveEnv } from '../../domain/sensitivity.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, inRuntimeInternals, report, type RecordFn } from './support.js';

/**
 * Intercepts reads of secret-looking environment variables via a Proxy over
 * `process.env`.
 *
 * Only variables whose name matches the secret pattern are inspected — mundane
 * reads (NODE_ENV, PATH, …) pass straight through with no stack capture, which
 * keeps overhead negligible on the hot path. In enforce mode a disallowed read
 * throws before the value is returned.
 *
 * Two read paths are covered. The `get` trap catches `process.env.SECRET`,
 * destructuring, spread and `Object.entries`/`values` (all of which invoke
 * `[[Get]]` per key). `Object.getOwnPropertyDescriptor(process.env, 'SECRET')`
 * does **not** invoke `[[Get]]` — it reads the value straight out of the
 * descriptor, which was a way to lift a secret past the `get` trap entirely. So
 * the `getOwnPropertyDescriptor` trap hands back an *accessor* descriptor for a
 * sensitive variable instead of its data descriptor: enumerating names
 * (`Object.keys`, `for…in`, which only read `enumerable`) reports nothing, but
 * pulling the value out means calling the getter, which funnels through the
 * same report/deny path as a plain read.
 *
 * Limitation: code that destructures `process.env` at module-load time reads
 * the value once and escapes later interception. This is best-effort by design.
 */
export class EnvInterceptor implements CapabilityInterceptor {
  readonly name = 'env';

  install(record: RecordFn): Disposable {
    const original = process.env;

    const guard = (prop: string): void => {
      // Skip reads made by another built-in's own implementation — see
      // `inRuntimeInternals`. Those are plumbing, not anyone's decision.
      if (isSensitiveEnv(prop) && !inRuntimeInternals()) {
        const decision = report(record, 'env.read', prop);
        if (!decision.allow) {
          throw blockedError(`env read of ${prop}`, decision.reason);
        }
      }
    };

    const proxy = new Proxy(original, {
      get(target, prop, receiver): unknown {
        if (typeof prop === 'string') {
          guard(prop);
        }
        return Reflect.get(target, prop, receiver);
      },
      set(target, prop, value): boolean {
        // Write straight to the real environment, deliberately *not* passing a
        // receiver.
        //
        // Without this trap, `process.env.X = y` through a proxy re-enters as
        // `[[DefineOwnProperty]]` on the receiver with a value-only descriptor,
        // and Node's `process.env` refuses partial descriptors outright:
        // `TypeError: 'process.env' only accepts a configurable, writable, and
        // enumerable data descriptor`.
        //
        // That one throw is why **`dephawk guard npm ci` did nothing at all**
        // for every release up to 0.6.5: npm assigns `env.HOME` while loading
        // its config, the TypeError propagated out of `Config.load`, and npm
        // exited 1 in silence — no install, no message, not even its own debug
        // log. Any proxy over `process.env` was enough; nothing else about
        // dephawk was involved.
        return Reflect.set(target, prop, value);
      },
      getOwnPropertyDescriptor(target, prop): PropertyDescriptor | undefined {
        const real = Reflect.getOwnPropertyDescriptor(target, prop);
        if (
          real === undefined ||
          typeof prop !== 'string' ||
          !isSensitiveEnv(prop) ||
          real.configurable === false ||
          inRuntimeInternals()
        ) {
          return real;
        }
        // Hide the value behind a getter so the descriptor cannot leak it.
        return {
          enumerable: real.enumerable ?? true,
          configurable: true,
          get(): unknown {
            guard(prop);
            return Reflect.get(target, prop);
          },
          set(value: unknown): void {
            Reflect.set(target, prop, value);
          },
        };
      },
    });

    define(process, 'env', proxy);
    return {
      dispose(): void {
        define(process, 'env', original);
      },
    };
  }
}

function define(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    configurable: true,
    enumerable: true,
  });
}
