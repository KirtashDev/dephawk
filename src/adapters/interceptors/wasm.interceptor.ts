import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  callerLocation,
  patchMethod,
  report,
  restorer,
  type RecordFn,
} from './support.js';

/**
 * Node compiles its own bundled dependencies (undici's `llhttp` HTTP parser) to
 * WebAssembly, lazily, the first time `fetch`/the HTTP client is used. That is
 * the runtime's own plumbing, not a supply-chain decision — blocking it would
 * break `fetch` and invent an `(unattributed)` finding for Node itself. Those
 * compiles are reached directly from `node:internal/deps/…`; a dependency
 * staging its own wasm calls `WebAssembly.*` from its own frame. So the
 * *immediate* caller tells the two apart — and it stays distinct from the
 * timer/microtask frames a laundered deferred call arrives on, which are still
 * caught.
 */
const RUNTIME_WASM_CALLER = 'node:internal/deps/';

/** Promise-returning `WebAssembly` entry points that compile and/or run wasm. */
const ASYNC_METHODS = [
  'instantiate',
  'compile',
  'instantiateStreaming',
  'compileStreaming',
] as const;

/** Synchronous `WebAssembly` constructors: compile (`Module`) and run (`Instance`). */
const CONSTRUCTORS = ['Module', 'Instance'] as const;

/**
 * Intercepts WebAssembly compilation and execution.
 *
 * A payload can ship as a wasm blob and run outside the JavaScript surface the
 * other interceptors patch — the same evasion `vm` gives for staged JS source,
 * one format over. Reproduced: `WebAssembly.instantiate(bytes)` executed under
 * enforce mode with a deny-by-default policy and the report showed nothing.
 *
 * Recorded as `code.eval` — dynamically turning a byte blob into running code —
 * so it shares the `eval` policy switch and is default-deny. Both the async
 * entry points (`instantiate`/`compile` and their `*Streaming` forms) and the
 * synchronous constructors (`new WebAssembly.Module`, `new WebAssembly.Instance`)
 * are covered, so an attacker cannot dodge the async surface by compiling and
 * instantiating by hand. Async denials reject their promise; constructor
 * denials throw, before the module exists.
 *
 * Note: legitimate packages do use wasm (image/crypto codecs), so under
 * `--enforce` this is the one addition here with a real false-positive rate.
 * Such a package is allowlisted with `eval: true`, exactly like a `vm` user;
 * in observe mode it is only reported.
 */
export class WasmInterceptor implements CapabilityInterceptor {
  readonly name = 'wasm';

  install(record: RecordFn): Disposable {
    const wasm = (globalThis as { WebAssembly?: Record<string, unknown> }).WebAssembly;
    if (wasm === undefined) {
      return restorer([]);
    }

    const restores: (() => void)[] = [];

    for (const key of ASYNC_METHODS) {
      const restore = patchMethod(wasm, key, (original) =>
        function wrapped(this: unknown, ...args: unknown[]): unknown {
          if (callerLocation(wrapped).startsWith(RUNTIME_WASM_CALLER)) {
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          }
          const decision = report(record, 'code.eval', `WebAssembly.${key}`);
          if (!decision.allow) {
            return Promise.reject(blockedError('WebAssembly execution', decision.reason));
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    for (const key of CONSTRUCTORS) {
      const restore = patchMethod(wasm, key, (Original) =>
        function wrapped(this: unknown, ...args: unknown[]): unknown {
          if (!callerLocation(wrapped).startsWith(RUNTIME_WASM_CALLER)) {
            const decision = report(record, 'code.eval', `new WebAssembly.${key}`);
            if (!decision.allow) {
              throw blockedError('WebAssembly execution', decision.reason);
            }
          }
          return Reflect.construct(
            Original as unknown as new (...a: unknown[]) => object,
            args,
          );
        },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}
