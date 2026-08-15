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
 * Intercepts hijacking of the CommonJS module loader.
 *
 * A dependency that reassigns `Module.prototype._compile` (or `Module._load`,
 * `Module._resolveFilename`, or an entry of `require.extensions`) sees, and can
 * rewrite, the source of every module loaded after it. Prepending code to
 * another package's source makes that code run inside *that* package's module —
 * so it is attributed to the innocent package and inherits its allowlist.
 * Reproduced: a dependency injected a `readFileSync` into an allowlisted package
 * via `Module.prototype._compile` and read a secret it had no rule for, under
 * `--enforce` with a deny-by-default policy.
 *
 * This cannot be caught in the attributor — the injected code genuinely runs in
 * the victim's module. The tell is the *act of hooking the loader*, which is
 * recorded as `code.eval` (running code that was not there before) and denied by
 * default. Legitimate transpiler/loader hooks (`ts-node`, `@babel/register`,
 * `tsx`, `pirates`) do the same thing and are real code execution, so they are
 * allowlisted the same way any `vm` user is: `eval: true`.
 *
 * The hook points are turned into accessor properties whose setter reports the
 * assignment; Node's own reads through the getter are untouched. `_extensions`
 * is an object, so it is wrapped in a Proxy that reports writes to it — and its
 * slot is itself guarded so replacing the whole object is caught too.
 *
 * The guard accessors are **non-configurable**. An earlier version made them
 * `configurable: true`, which reopened the exact hole they close: a JS setter
 * only fires on assignment (`x = v`), never on `Object.defineProperty`, and a
 * configurable accessor can be replaced wholesale by `defineProperty` — so a
 * dependency did `Object.defineProperty(Module.prototype, '_compile', { value })`
 * and rewrote the loader with no `code.eval` ever reported, injecting code into
 * an allowlisted package under `--enforce`. This is the same `[[DefineOwnProperty]]`
 * bypass the env Proxy and `hardenedCapture` already defend against. A
 * non-configurable accessor makes that `defineProperty` throw instead. Because it
 * can never be reconfigured, it is installed once per process and steered through
 * a small registry so `dispose()`/re-install still work (deactivate, then
 * reactivate with the new recorder) across the lifecycle the tests exercise.
 */

/**
 * The live state behind one permanent guard accessor. Mutable so the accessor,
 * defined once, can be turned off on dispose and back on with a fresh recorder.
 */
interface Guard {
  active: boolean;
  record: RecordFn;
  detail: string;
  current: unknown;
}

/** Per-object registry of installed guards, keyed by property name. */
const GUARDS = new WeakMap<object, Map<string, Guard>>();

function guardMapFor(target: object): Map<string, Guard> {
  let map = GUARDS.get(target);
  if (map === undefined) {
    map = new Map();
    GUARDS.set(target, map);
  }
  return map;
}
export class ModuleLoaderInterceptor implements CapabilityInterceptor {
  readonly name = 'module-loader';

  install(record: RecordFn): Disposable {
    const Module = loadBuiltin<Record<string, unknown>>('node:module');
    const restores: (() => void)[] = [];

    const proto = (Module['prototype'] ?? {}) as Record<string, unknown>;
    guardAssignment(proto, '_compile', 'Module.prototype._compile', record, restores);
    guardAssignment(Module, '_load', 'Module._load', record, restores);
    guardAssignment(
      Module,
      '_resolveFilename',
      'Module._resolveFilename',
      record,
      restores,
    );
    guardExtensions(Module, record, restores);

    // The ESM equivalent: `module.register(hook)` (and the synchronous
    // `registerHooks`) install a customisation hook that can rewrite the source
    // of every ES module loaded afterwards. Unlike the `Module.*` internals
    // above, these are *called*, not reassigned, so they are patched as methods.
    for (const key of ['register', 'registerHooks'] as const) {
      const restore = patchMethod(
        Module,
        key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            const decision = report(record, 'code.eval', `module.${key} (loader hook)`);
            if (!decision.allow) {
              throw blockedError(
                `ES module loader hook via module.${key}`,
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

/**
 * Install (once) a permanent, non-configurable accessor over `target[key]` whose
 * setter reports `code.eval`, and return its {@link Guard}. Reads return the
 * current value, so Node calling the built-in is unaffected; both an assignment
 * (`x = v`, caught by the setter) and an `Object.defineProperty` (which throws on
 * the non-configurable accessor) are refused. Re-install reactivates the existing
 * accessor with the new recorder rather than redefining it. Returns null when the
 * accessor could not be installed.
 */
function installGuard(
  target: Record<string, unknown>,
  key: string,
  detail: string,
  record: RecordFn,
  initial: unknown,
  restores: (() => void)[],
): Guard | null {
  const map = guardMapFor(target);
  const existing = map.get(key);
  if (existing !== undefined) {
    existing.record = record;
    existing.detail = detail;
    existing.active = true;
    restores.push(() => {
      existing.active = false;
    });
    return existing;
  }
  const guard: Guard = { active: true, record, detail, current: initial };
  try {
    Object.defineProperty(target, key, {
      configurable: false,
      enumerable: true,
      get(): unknown {
        return guard.current;
      },
      set(value: unknown): void {
        if (guard.active) {
          const decision = report(
            guard.record,
            'code.eval',
            `${guard.detail} (loader hook)`,
          );
          if (!decision.allow) {
            throw blockedError(`module loader hook on ${guard.detail}`, decision.reason);
          }
        }
        guard.current = value;
      },
    });
  } catch {
    return null; // already a non-configurable data property, or frozen
  }
  map.set(key, guard);
  restores.push(() => {
    guard.active = false;
  });
  return guard;
}

/**
 * Guard `target[key]` (a loader-hook function slot) against both assignment and
 * `Object.defineProperty` replacement.
 */
function guardAssignment(
  target: Record<string, unknown>,
  key: string,
  detail: string,
  record: RecordFn,
  restores: (() => void)[],
): void {
  const already = GUARDS.get(target)?.has(key) ?? false;
  const original = target[key];
  if (!already && typeof original !== 'function') {
    return;
  }
  installGuard(target, key, detail, record, original, restores);
}

/**
 * Guard `Module._extensions` (aka `require.extensions`) two ways: a Proxy over
 * the object reports a write to any handler (the `@babel/register` style hook),
 * and the slot itself is a guarded accessor so replacing the whole object
 * (`Module._extensions = { … }`) is caught too. Both `set` and `defineProperty`
 * are trapped on the Proxy so neither spelling of a per-key write slips by.
 */
function guardExtensions(
  Module: Record<string, unknown>,
  record: RecordFn,
  restores: (() => void)[],
): void {
  const map = guardMapFor(Module);
  const existing = map.get('_extensions');
  if (existing !== undefined) {
    existing.record = record;
    existing.active = true;
    restores.push(() => {
      existing.active = false;
    });
    return;
  }
  const original = Module['_extensions'];
  if (typeof original !== 'object' || original === null) {
    return;
  }
  // The guard is referenced by the Proxy traps (so they use the live recorder and
  // honour deactivation), so build it before the Proxy and set `current` after.
  const guard: Guard = {
    active: true,
    record,
    detail: 'require.extensions',
    current: undefined,
  };
  const reportWrite = (key: PropertyKey): void => {
    if (!guard.active) {
      return;
    }
    const decision = report(
      guard.record,
      'code.eval',
      `require.extensions[${String(key)}]`,
    );
    if (!decision.allow) {
      throw blockedError(`require.extensions hook (${String(key)})`, decision.reason);
    }
  };
  const proxy = new Proxy(original as Record<string, unknown>, {
    set(t, key, value): boolean {
      reportWrite(key);
      return Reflect.set(t, key, value);
    },
    defineProperty(t, key, descriptor): boolean {
      reportWrite(key);
      return Reflect.defineProperty(t, key, descriptor);
    },
  });
  guard.current = proxy;
  try {
    Object.defineProperty(Module, '_extensions', {
      configurable: false,
      enumerable: true,
      get(): unknown {
        return guard.current;
      },
      set(value: unknown): void {
        if (guard.active) {
          const decision = report(
            guard.record,
            'code.eval',
            'require.extensions (reassigned)',
          );
          if (!decision.allow) {
            throw blockedError('reassigning require.extensions', decision.reason);
          }
        }
        guard.current = value;
      },
    });
  } catch {
    return;
  }
  map.set('_extensions', guard);
  restores.push(() => {
    guard.active = false;
  });
}
