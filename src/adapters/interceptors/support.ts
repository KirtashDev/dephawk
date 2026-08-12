import type { Decision, InterceptedCall } from '../../application/ports.js';
import type { Capability } from '../../domain/capability.js';
import { redactSecrets } from '../../domain/redact.js';

/**
 * `createRequire`, obtained through `process.getBuiltinModule` rather than
 * `import { createRequire } from 'node:module'`.
 *
 * The import form would build the `node:module` ESM facade here, snapshotting
 * that module's named exports — `module.register` among them — to their
 * originals before the module-loader interceptor patches them, which would let a
 * dependency install an ES-module source-rewriting hook with
 * `import { register } from 'node:module'`. `getBuiltinModule` returns the
 * module without creating the facade (verified on Node 20 and 22), so the facade
 * is built later, by the application or a dependency, after the patch. It is the
 * same reasoning as {@link loadBuiltin} — this is simply the one built-in
 * dephawk needs before `loadBuiltin` itself exists.
 */
const getBuiltinModule = (
  process as unknown as {
    getBuiltinModule?: (id: string) => { createRequire(url: string): NodeRequire };
  }
).getBuiltinModule;
const nodeRequire = getBuiltinModule!('node:module').createRequire(import.meta.url);

/**
 * Load a built-in module through `require`, not `import`, and this is
 * load-bearing rather than a style choice.
 *
 * `import fs from 'node:fs'` builds the module's ESM facade, whose **named**
 * exports (`import { readFileSync } from 'node:fs'`) are bound to the functions
 * that exist at the moment the facade is first created — a snapshot, not a live
 * view. If dephawk creates that facade (by importing the built-in) before it
 * patches, the snapshot captures the *original* functions, and a dependency
 * written as ESM sails straight past every interceptor with
 * `import { readFileSync } from 'node:fs'`. Reproduced: an ESM dependency read a
 * secret under `--enforce` with a deny-by-default policy, invisible in the
 * report.
 *
 * `require` returns the module object *without* creating the facade. So every
 * interceptor takes its built-in this way, patches it, and only then — when the
 * application or a dependency first does `import … from 'node:fs'` — is the
 * facade built, snapshotting the functions dephawk has already replaced.
 */
export function loadBuiltin<T = unknown>(id: string): T {
  return nodeRequire(id) as T;
}

/** The record callback interceptors are wired to. */
export type RecordFn = (call: InterceptedCall) => Decision;

/**
 * Frame budget used while capturing a stack for attribution. Generous, because
 * the attributor scans every frame for the first `node_modules/<pkg>` owner —
 * truncating the stack could drop the culprit and misread the call as the
 * application's. Restored immediately after each capture.
 */
const STACK_CAPTURE_LIMIT = 100;

/**
 * The genuine `Error` constructor and `Error.captureStackTrace`, taken once at
 * module load.
 *
 * Everything about attribution rests on the stack being the real one, and both
 * of these are writable globals. `register.js` runs before any dependency is
 * loaded, so what we grab here is V8's own — reading them live at capture time
 * would let a dependency swap in a function that returns whatever stack it
 * likes. That is not hypothetical: replacing `Error.captureStackTrace` with one
 * that writes a frame naming an application file makes the call read as *your*
 * code, which the policy engine allows unconditionally. Reproduced reading a
 * real secret under `--enforce` with a deny-by-default policy.
 *
 * The same reasoning covers the `prepareStackTrace`/`stackTraceLimit` overrides
 * below: they are set on this captured constructor rather than on the live
 * `Error` global, so swapping the global out does not move the knobs we set.
 */
const NativeError = Error;
const nativeCaptureStackTrace = Error.captureStackTrace;

/**
 * dephawk's own `Error.prepareStackTrace`, installed only for the duration of a
 * capture. Two jobs:
 *
 * 1. It replaces whatever formatter a dependency may have set, so a forged one
 *    cannot run while we capture (the same reason we used to force `undefined`).
 * 2. It marks every **eval-defined** frame with the sentinel location
 *    {@link EVAL_FRAME}, discarding the file name and eval origin V8 reports for
 *    it. A `//# sourceURL=/app/x.js` comment inside evaluated source forges
 *    *both* `getFileName()` and `getEvalOrigin()`, so a dependency could define a
 *    function in `eval("//# sourceURL=/app/x.js\n…")` and have every later call
 *    to it read as first-party application code, unconditionally allowed under
 *    `--enforce`. `isEval()` cannot be forged, so the attributor is told the
 *    frame is dynamically-generated code and refuses it application trust (see
 *    the `eval` frame kind in the stack attributor).
 *
 * Defensive throughout: any failure falls back to the frame's own default
 * string, and the whole thing to `'Error'` — a formatter that throws would break
 * every capture.
 */
export const EVAL_FRAME = '[eval]';

function formatStack(_error: unknown, frames: readonly NodeJS.CallSite[]): string {
  try {
    let out = 'Error';
    for (const frame of frames) {
      out += `\n    at ${formatFrame(frame)}`;
    }
    return out;
  } catch {
    return 'Error';
  }
}

function formatFrame(frame: NodeJS.CallSite): string {
  try {
    const name = frame.getFunctionName() ?? frame.getMethodName() ?? '';
    if (frame.isEval()) {
      // Its reported location is attacker-controllable via `//# sourceURL`; the
      // only trustworthy fact is that it is eval-defined.
      return name.length > 0 ? `${name} (${EVAL_FRAME})` : EVAL_FRAME;
    }
    const file = frame.getFileName() ?? (frame.isNative() ? 'native' : '<anonymous>');
    const location = `${file}:${frame.getLineNumber() ?? 0}:${frame.getColumnNumber() ?? 0}`;
    return name.length > 0 ? `${name} (${location})` : location;
  } catch {
    try {
      return String(frame);
    } catch {
      return '<frame>';
    }
  }
}

/**
 * Capture a stack string with dephawk's own formatter forcibly in control.
 *
 * The formatter is installed with `Object.defineProperty` — a *data* descriptor,
 * not a plain assignment. Assignment (`Error.prepareStackTrace = formatStack`)
 * invokes any setter a dependency planted, and an accessor with a no-op setter
 * swallows the write silently: dephawk would believe its formatter was active
 * while the dependency's forging getter still ran, forging an application frame
 * that is trusted for every capability under `--enforce`. A `defineProperty` with
 * a data value *replaces* that accessor for the duration of the capture.
 *
 * After installing, we verify the active value really is our formatter. If a
 * dependency made the property non-configurable (so `defineProperty` throws) —
 * the narrower, more conspicuous "frozen" residual — we return an **empty**
 * stack rather than a forgeable one, so attribution falls to `unknown` (the
 * default, deny-by-default bucket) instead of believing a planted frame.
 *
 * The saved *descriptor* (not just the value) is restored in `finally`, so the
 * dependency's own error handling is untouched afterwards.
 */
function hardenedCapture(boundary: (...args: never[]) => unknown): string {
  const capture = nativeCaptureStackTrace as
    ((target: object, ctor?: (...args: never[]) => unknown) => void) | undefined;
  const errorGlobal = NativeError as unknown as {
    prepareStackTrace?: unknown;
    stackTraceLimit?: number | undefined;
  };
  const savedDescriptor = Object.getOwnPropertyDescriptor(
    NativeError,
    'prepareStackTrace',
  );
  const savedLimit = errorGlobal.stackTraceLimit;

  let installed = false;
  try {
    Object.defineProperty(NativeError, 'prepareStackTrace', {
      value: formatStack,
      configurable: true,
      writable: true,
      enumerable: false,
    });
    installed = errorGlobal.prepareStackTrace === formatStack;
  } catch {
    installed = false; // non-configurable / frozen — documented residual
  }
  if (typeof savedLimit !== 'number' || savedLimit < STACK_CAPTURE_LIMIT) {
    try {
      errorGlobal.stackTraceLimit = STACK_CAPTURE_LIMIT;
    } catch {
      /* frozen — best effort */
    }
  }
  try {
    if (!installed) {
      return ''; // could not guarantee our formatter — do not trust a forged stack
    }
    if (typeof capture === 'function') {
      const holder: { stack?: string } = {};
      capture(holder, boundary);
      return holder.stack ?? '';
    }
    return new NativeError().stack ?? '';
  } finally {
    try {
      if (savedDescriptor !== undefined) {
        Object.defineProperty(NativeError, 'prepareStackTrace', savedDescriptor);
      } else {
        delete (NativeError as unknown as { prepareStackTrace?: unknown })
          .prepareStackTrace;
      }
    } catch {
      /* frozen — nothing to restore */
    }
    try {
      errorGlobal.stackTraceLimit = savedLimit;
    } catch {
      /* frozen */
    }
  }
}

export function captureStack(): string {
  return hardenedCapture(captureStack);
}

/** Emit a record for a capability and return the decision. */
export function report(
  record: RecordFn,
  capability: Capability,
  detail: string,
  valueSensitive = false,
): Decision {
  return record({
    capability,
    detail,
    rawStack: captureStack(),
    ...(valueSensitive ? { valueSensitive: true } : {}),
  });
}

/**
 * The source location of the frame that called `boundary` — the immediate
 * external caller of a wrapper, with `boundary` and everything above it removed
 * (`at fn (LOC)` → `LOC`). Empty string when it cannot be determined.
 *
 * Used to tell a capability the *runtime itself* exercises apart from the same
 * capability reached by a dependency: they differ only in who the direct caller
 * is. Node compiles its bundled undici/llhttp parser through
 * `WebAssembly.instantiate`, and blocking that would break `fetch` and invent a
 * finding for Node's own plumbing — see the
 * {@link import('./wasm.interceptor.js').WasmInterceptor}.
 */
export function callerLocation(boundary: (...args: never[]) => unknown): string {
  // Shares captureStack's hardening: without it, a dependency's forged
  // `Error.prepareStackTrace` governs this output, and it could fake a
  // `node:internal/deps/` caller to make the WASM interceptor treat its payload
  // as Node's own undici plumbing and skip it entirely. A defeated install
  // yields an empty stack here, so the `node:internal/deps/` prefix check fails
  // closed (the call is recorded, not skipped).
  const stack = hardenedCapture(boundary);
  for (const line of stack.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('at ')) {
      const open = trimmed.indexOf('(');
      const location =
        open !== -1 && trimmed.endsWith(')')
          ? trimmed.slice(open + 1, -1)
          : trimmed.slice('at '.length);
      return location.replace(/\\/g, '/');
    }
  }
  return '';
}

/** A loosely-typed function, used only at the Node monkey-patch boundary. */
export type AnyFn = (...args: any[]) => any;

/**
 * Every wrapper {@link patchMethod} installs, so we can recognise one later.
 *
 * A `WeakSet` rather than a marker property: it adds nothing observable to the
 * built-ins we patch, and it cannot be forged by code that only holds the
 * function. The
 * {@link import('./scheduler.interceptor.js').SchedulerInterceptor} uses it to
 * spot an intercepted built-in being handed straight to a scheduler, which is
 * the shape of a call whose owner will have vanished by the time it runs.
 */
const wrappers = new WeakSet<AnyFn>();

/** Whether `value` is a dephawk wrapper around a Node built-in. */
export function isWrapper(value: unknown): value is AnyFn {
  return typeof value === 'function' && wrappers.has(value as AnyFn);
}

/** Own properties that belong to the wrapper itself and must not be copied. */
const INTRINSIC_PROPS = new Set(['length', 'name', 'prototype', 'arguments', 'caller']);

/**
 * Carry the original's own properties onto the wrapper. Node hangs real API on
 * some built-ins — `setTimeout[util.promisify.custom]`, `fs.realpath.native` —
 * and dropping it would break callers that never asked to be monitored.
 */
function inheritProps(original: AnyFn, wrapped: AnyFn): void {
  for (const key of Reflect.ownKeys(original)) {
    if (typeof key === 'string' && INTRINSIC_PROPS.has(key)) {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(original, key);
    if (descriptor === undefined) {
      continue;
    }
    try {
      Object.defineProperty(wrapped, key, descriptor);
    } catch {
      // Non-configurable on the wrapper — nothing we can do, and not worth
      // failing the whole install over.
    }
  }
}

/**
 * Replace `target[key]` with `wrap(original)`, returning a restore function.
 * If the member is not a function (missing on this runtime), returns null so
 * the caller can degrade gracefully rather than crash.
 */
export function patchMethod<T extends Record<string, any>>(
  target: T,
  key: keyof T & string,
  wrap: (original: AnyFn) => AnyFn,
): (() => void) | null {
  const original = target[key];
  if (typeof original !== 'function') {
    return null;
  }
  const wrapped = wrap(original as AnyFn);
  inheritProps(original as AnyFn, wrapped);
  wrappers.add(wrapped);
  Object.defineProperty(target, key, {
    value: wrapped,
    writable: true,
    configurable: true,
    enumerable: Object.prototype.propertyIsEnumerable.call(target, key),
  });
  return () => {
    Object.defineProperty(target, key, {
      value: original,
      writable: true,
      configurable: true,
      enumerable: Object.prototype.propertyIsEnumerable.call(target, key),
    });
  };
}

/**
 * The `.prototype` of a constructor-like value, or null when the value is not a
 * function or has no object prototype. Lets interceptors patch class prototype
 * methods (`dns.Resolver`, `dgram.Socket`, `vm.Script`) without unsafe casts,
 * degrading gracefully when a runtime does not expose the class.
 */
export function prototypeOf(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'function') {
    return null;
  }
  const proto = (value as { prototype?: unknown }).prototype;
  return typeof proto === 'object' && proto !== null
    ? (proto as Record<string, unknown>)
    : null;
}

/** A disposable that runs a set of restore callbacks exactly once. */
export function restorer(restores: readonly (() => void)[]): { dispose(): void } {
  let done = false;
  return {
    dispose(): void {
      if (done) {
        return;
      }
      done = true;
      for (const restore of restores) {
        restore();
      }
    },
  };
}

/**
 * Depth of nested calls currently executing Node's own implementation of an
 * intercepted built-in.
 *
 * Some built-ins read others on the way through. `child_process` copies the
 * whole of `process.env` inside `normalizeSpawnArguments` to build the child's
 * environment, which the env interceptor's proxy sees as the calling package
 * reading every secret in the environment — five invented findings for one
 * `execSync('echo hi')`, and, worse, a drafted policy that hands that package
 * every secret it never asked for. Those reads are the runtime's plumbing, not
 * a decision by anyone's code, so they are not recorded.
 *
 * A package that genuinely reads a secret and passes it to a child does so in
 * its own code, before the call, and is still caught.
 */
let runtimeDepth = 0;

/** Run Node's own implementation of an intercepted call. */
export function asRuntimeInternals<T>(fn: () => T): T {
  runtimeDepth += 1;
  try {
    return fn();
  } finally {
    runtimeDepth -= 1;
  }
}

/** Whether we are currently inside a built-in's own implementation. */
export function inRuntimeInternals(): boolean {
  return runtimeDepth > 0;
}

/**
 * Build a blocked-call error with a consistent, greppable prefix.
 *
 * Redacted like the report is: this message reaches stderr, and under `guard`
 * that stderr is a CI log. A blocked spawn's detail is the command line it was
 * about to run, secrets and all.
 */
export function blockedError(detail: string, reason: string): Error {
  return new Error(`dephawk: blocked ${redactSecrets(detail)} — ${reason}`);
}
