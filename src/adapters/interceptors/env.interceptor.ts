import { isSensitiveEnv } from '../../domain/sensitivity.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  inRuntimeInternals,
  loadBuiltin,
  report,
  type RecordFn,
} from './support.js';

/**
 * Intercepts reads of secret-looking environment variables via a Proxy over
 * `process.env`.
 *
 * Only variables whose name matches the secret pattern are inspected — mundane
 * reads (NODE_ENV, PATH, …) pass straight through with no stack capture, which
 * keeps overhead negligible on the hot path. In enforce mode a disallowed read
 * throws before the value is returned.
 *
 * Three read paths are covered:
 *
 * 1. The `get` trap catches `process.env.SECRET`, destructuring, spread and
 *    `Object.entries`/`values` (all of which invoke `[[Get]]` per key).
 *
 * 2. `Object.getOwnPropertyDescriptor(process.env, 'SECRET')` does **not** invoke
 *    `[[Get]]` — it reads the value straight out of the descriptor, which was a
 *    way to lift a secret past the `get` trap entirely. So the
 *    `getOwnPropertyDescriptor` trap hands back an *accessor* descriptor for a
 *    sensitive variable instead of its data descriptor: enumerating names
 *    (`Object.keys`, `for…in`, which only read `enumerable`) reports nothing, but
 *    pulling the value out means calling the getter, which funnels through the
 *    same report/deny path as a plain read.
 *
 * 3. `util.inspect(process.env)` — and therefore `console.log(process.env)`,
 *    `console.dir`, and every logger that formats objects — reads **no trap at
 *    all**. V8 unwraps a Proxy to its *target* through the internal
 *    `getProxyDetails` and formats the target's own values directly. With the
 *    real `process.env` as the target that dumped every variable, secrets
 *    included, past all the other traps in a single call (reported nothing,
 *    denied nothing). So the Proxy sits over an empty *decoy* target and every
 *    trap forwards to the real environment: an unwrap finds no values to print. A
 *    `util.inspect.custom` hook on the decoy judges the dump: it exposes the
 *    whole environment at once — the same threat as `process.report.getReport()`
 *    — so it is recorded as `process.memory` and, for a dependency without
 *    `memory: true`, hidden behind a placeholder. Your own code (and a dependency
 *    that is allowed) still sees the real thing.
 *
 * Limitation: code that destructures `process.env` at module-load time reads the
 * value once and escapes later interception. This is best-effort by design.
 */
export class EnvInterceptor implements CapabilityInterceptor {
  readonly name = 'env';

  install(record: RecordFn): Disposable {
    const original = process.env;
    const inspectCustom = (loadBuiltin('node:util') as { inspect: { custom: symbol } })
      .inspect.custom;

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

    // The target the Proxy wraps is a decoy, *not* `process.env`. `util.inspect`
    // (and thus `console.log`) unwraps a Proxy straight to its target and reads
    // the target's own values with no trap in the way — so the target must hold
    // no values. All traps below forward to the real environment (`original`).
    const decoy: Record<string | symbol, unknown> = {};
    Object.defineProperty(decoy, inspectCustom, {
      value(
        _depth: number,
        options: unknown,
        inspect: (value: unknown, options: unknown) => string,
      ): string {
        // Format the real environment as inspect normally would — used when the
        // caller is allowed to see it (your own code, or a dependency with
        // `memory: true`). The spread is a plain snapshot, so inspecting it does
        // not re-enter this proxy.
        const reveal = (): string => inspect({ ...original }, options);

        // Node's own object-formatting plumbing: stay transparent, record
        // nothing.
        if (inRuntimeInternals()) {
          return reveal();
        }

        // A whole-environment dump exposes every variable, secrets included, in
        // one call — the same threat as `process.report.getReport()`, so it is
        // judged as `process.memory` (deny-by-default). Never throw here: this
        // runs inside object formatting, and a throw would break every
        // `console.log` in the process. A denied dump is hidden, not fatal.
        const decision = report(record, 'process.memory', 'process.env via util.inspect');
        return decision.allow
          ? reveal()
          : '[process.env — hidden by dephawk; read a named variable to access it]';
      },
      enumerable: false,
      configurable: true,
      writable: true,
    });

    const proxy = new Proxy(decoy, {
      get(_target, prop, receiver): unknown {
        if (prop === inspectCustom) {
          return Reflect.get(decoy, prop, receiver);
        }
        if (typeof prop === 'string') {
          guard(prop);
        }
        return Reflect.get(original, prop);
      },
      set(_target, prop, value): boolean {
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
        return Reflect.set(original, prop, value);
      },
      has(_target, prop): boolean {
        return Reflect.has(original, prop);
      },
      deleteProperty(_target, prop): boolean {
        return Reflect.deleteProperty(original, prop);
      },
      ownKeys(): (string | symbol)[] {
        return Reflect.ownKeys(original);
      },
      defineProperty(_target, prop, descriptor): boolean {
        // `Object.defineProperty(process.env, …)` must land on the real
        // environment, not the decoy.
        return Reflect.defineProperty(original, prop, descriptor);
      },
      getOwnPropertyDescriptor(_target, prop): PropertyDescriptor | undefined {
        const real = Reflect.getOwnPropertyDescriptor(original, prop);
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
            return Reflect.get(original, prop);
          },
          set(value: unknown): void {
            Reflect.set(original, prop, value);
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
