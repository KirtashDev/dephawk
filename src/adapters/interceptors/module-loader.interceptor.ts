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
 * is an object, so it is wrapped in a Proxy that reports writes to it.
 */
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
 * Turn `target[key]` into an accessor whose setter reports `code.eval`. Reads
 * return the current value, so Node calling the built-in is unaffected; an
 * assignment is refused in enforce mode before it takes effect.
 */
function guardAssignment(
  target: Record<string, unknown>,
  key: string,
  detail: string,
  record: RecordFn,
  restores: (() => void)[],
): void {
  const original = target[key];
  if (typeof original !== 'function') {
    return;
  }
  let current: unknown = original;
  try {
    Object.defineProperty(target, key, {
      configurable: true,
      enumerable: true,
      get(): unknown {
        return current;
      },
      set(value: unknown): void {
        const decision = report(record, 'code.eval', `${detail} (loader hook)`);
        if (!decision.allow) {
          throw blockedError(`module loader hook on ${detail}`, decision.reason);
        }
        current = value;
      },
    });
  } catch {
    return; // frozen by something else; best effort
  }
  restores.push(() => {
    try {
      Object.defineProperty(target, key, {
        value: current,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch {
      /* nothing we can do */
    }
  });
}

/**
 * Wrap `Module._extensions` (aka `require.extensions`) in a Proxy that reports a
 * write to any of its handlers — the `@babel/register` style of loader hook.
 */
function guardExtensions(
  Module: Record<string, unknown>,
  record: RecordFn,
  restores: (() => void)[],
): void {
  const original = Module['_extensions'];
  if (typeof original !== 'object' || original === null) {
    return;
  }
  const proxy = new Proxy(original as Record<string, unknown>, {
    set(t, key, value): boolean {
      const decision = report(record, 'code.eval', `require.extensions[${String(key)}]`);
      if (!decision.allow) {
        throw blockedError(`require.extensions hook (${String(key)})`, decision.reason);
      }
      return Reflect.set(t, key, value);
    },
  });
  try {
    Object.defineProperty(Module, '_extensions', {
      value: proxy,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  } catch {
    return;
  }
  restores.push(() => {
    try {
      Object.defineProperty(Module, '_extensions', {
        value: original,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch {
      /* nothing we can do */
    }
  });
}
