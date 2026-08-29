import { isSensitiveEnv, looksLikeSecretValue } from '../../domain/sensitivity.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  inRuntimeInternals,
  loadBuiltin,
  report,
  type RecordFn,
} from './support.js';

/**
 * Environment variables whose *writes* are recorded.
 *
 * `process.env` writes used to be a silent hole: the `set` and `defineProperty`
 * traps forwarded to the real environment and recorded nothing. Real 2026
 * campaigns walked through it —
 *
 * - mastra set `NODE_TLS_REJECT_UNAUTHORIZED='0'`, turning off certificate
 *   validation for the whole process before exfiltrating;
 * - vpmdhaj rewrote `CI='false'` to mislead build-aware code paths after using
 *   the same variable for sandbox detection;
 * - and the same trap is where a dependency would scrub `NODE_OPTIONS` or
 *   `DEPHAWK_*` to blind dephawk from the inside.
 *
 * A denylist rather than recording every write, deliberately: `process.env.X =
 * y` is ordinary in a build (npm alone does it while loading its config), so
 * recording all of them would bury the four that matter and put a report/deny
 * round-trip on a hot path. Everything here is non-secret by construction, so
 * the value can be carried in the detail — and it must be, because `=0` and `=1`
 * on `NODE_TLS_REJECT_UNAUTHORIZED` are opposite findings.
 *
 * Scrubbing `NODE_OPTIONS`/`DEPHAWK_*` is *recorded* rather than mandatorily
 * refused: children are repaired from the install-time snapshot on every spawn
 * (see {@link import('./monitored-env.js')}), so the scrub already achieves
 * nothing — what it deserves is to be named.
 */
const GUARDED_ENV_WRITES: ReadonlySet<string> = new Set([
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_OPTIONS',
  'NODE_EXTRA_CA_CERTS',
  'CI',
]);

/** dephawk's own settings, all of which are guarded by prefix. */
const GUARDED_ENV_PREFIX = 'DEPHAWK_';

/**
 * Compared upper-cased: `process.env` is case-insensitive on Windows, so
 * `node_options` sets the same variable as `NODE_OPTIONS` and a case-sensitive
 * check would be a one-character bypass there.
 */
function isGuardedEnvWrite(name: string): boolean {
  const upper = name.toUpperCase();
  return GUARDED_ENV_WRITES.has(upper) || upper.startsWith(GUARDED_ENV_PREFIX);
}

/** A value rendered for the report, never throwing (a symbol would). */
function show(value: unknown): string {
  try {
    return String(value);
  } catch {
    return '<unprintable>';
  }
}

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
 * Writes are covered too, but only for {@link GUARDED_ENV_WRITES} — the handful
 * of variables whose value decides how the *process* behaves rather than what
 * some library does with it. Every trap that mutates the environment (`set`,
 * `defineProperty`, `deleteProperty`, and the accessor handed back by
 * `getOwnPropertyDescriptor`) funnels through the same check.
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

    const guard = (prop: string, value: unknown): void => {
      // Skip reads made by another built-in's own implementation — see
      // `inRuntimeInternals`. Those are plumbing, not anyone's decision.
      if (inRuntimeInternals()) {
        return;
      }
      // Sensitive by name, or by value: `DATABASE_URL=postgres://u:pass@host` is
      // a secret its innocuous name hides. Only a boolean flag is reported — the
      // value never leaves this interceptor.
      const byName = isSensitiveEnv(prop);
      const byValue = !byName && looksLikeSecretValue(value);
      if (!byName && !byValue) {
        return;
      }
      const decision = report(record, 'env.read', prop, byValue);
      if (!decision.allow) {
        throw blockedError(`env read of ${prop}`, decision.reason);
      }
    };

    /**
     * Judge a mutation of a guarded variable. `detail` carries the new value
     * (`NODE_OPTIONS=--require x`) or the deletion marker, because that is what
     * the finding is about.
     */
    const guardWrite = (prop: string, detail: string): void => {
      // dephawk's own repair of the child environment before a spawn runs
      // through this proxy; that is plumbing, not the caller's decision.
      if (inRuntimeInternals() || !isGuardedEnvWrite(prop)) {
        return;
      }
      const decision = report(record, 'env.write', detail);
      if (!decision.allow) {
        throw blockedError(`env write of ${prop}`, decision.reason);
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
          const value = Reflect.get(original, prop);
          guard(prop, value);
          return value;
        }
        return Reflect.get(original, prop);
      },
      set(_target, prop, value): boolean {
        if (typeof prop === 'string') {
          guardWrite(prop, `${prop}=${show(value)}`);
        }
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
        if (typeof prop === 'string') {
          // Deleting is how monitoring gets scrubbed, so it is the same finding
          // as setting — `delete process.env.NODE_OPTIONS` and
          // `process.env.NODE_OPTIONS = ''` are the same move.
          guardWrite(prop, `${prop} (deleted)`);
        }
        return Reflect.deleteProperty(original, prop);
      },
      ownKeys(): (string | symbol)[] {
        return Reflect.ownKeys(original);
      },
      defineProperty(_target, prop, descriptor): boolean {
        if (typeof prop === 'string') {
          // `Object.defineProperty` reaches the environment without the `set`
          // trap, which would otherwise be a way to disable TLS unrecorded.
          guardWrite(prop, `${prop}=${show(descriptor.value)}`);
        }
        // `Object.defineProperty(process.env, …)` must land on the real
        // environment, not the decoy.
        return Reflect.defineProperty(original, prop, descriptor);
      },
      preventExtensions(): boolean {
        // Forward to the real environment, which refuses (`process.env` cannot
        // be made non-extensible). Crucially this keeps the *decoy* extensible:
        // if the decoy were ever sealed, `ownKeys` returning the real
        // environment's names — none of which exist on the empty decoy — would
        // violate the Proxy invariant and make every `Object.keys(process.env)`,
        // spread and `console.log` throw. Mirrors real `process.env`:
        // `Object.preventExtensions` throws, `Reflect.preventExtensions` is false.
        return Reflect.preventExtensions(original);
      },
      getPrototypeOf(): object | null {
        // The decoy is a plain object, but `process.env` has its own special
        // prototype. Forwarding keeps `Object.getPrototypeOf(process.env)`
        // identical to an unwrapped env — otherwise the mismatch is both a
        // fidelity break and a way for a dependency to *detect* it is being
        // monitored (and change behaviour) by testing the prototype.
        return Reflect.getPrototypeOf(original);
      },
      setPrototypeOf(_target, proto): boolean {
        return Reflect.setPrototypeOf(original, proto);
      },
      getOwnPropertyDescriptor(_target, prop): PropertyDescriptor | undefined {
        const real = Reflect.getOwnPropertyDescriptor(original, prop);
        // Hide the value behind a getter for a secret var — by name, or by value
        // (a connection string) — so `getOwnPropertyDescriptor(...).value` cannot
        // lift it past the `get` trap.
        if (
          real === undefined ||
          typeof prop !== 'string' ||
          real.configurable === false ||
          inRuntimeInternals() ||
          !(isSensitiveEnv(prop) || looksLikeSecretValue(real.value))
        ) {
          return real;
        }
        return {
          enumerable: real.enumerable ?? true,
          configurable: true,
          get(): unknown {
            const value = Reflect.get(original, prop);
            guard(prop, value);
            return value;
          },
          set(value: unknown): void {
            // Reached via `getOwnPropertyDescriptor(process.env, X).set(…)`;
            // same mutation, same judgement.
            guardWrite(prop, `${prop}=${show(value)}`);
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
