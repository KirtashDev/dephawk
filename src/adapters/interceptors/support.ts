import type { Decision, InterceptedCall } from '../../application/ports.js';
import type { Capability } from '../../domain/capability.js';
import { redactSecrets } from '../../domain/redact.js';

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
 * Capture the current stack as a string, excluding this helper's own frame.
 * Uses V8's `Error.captureStackTrace` when available (fast, no Error object
 * exposed) and degrades to `new Error().stack` elsewhere (Bun/Deno).
 *
 * Both `Error.prepareStackTrace` and `Error.stackTraceLimit` are globals a
 * dependency can write. Left alone, a dependency can **forge attribution**: set
 * `Error.prepareStackTrace` to a function returning a stack string with a fake
 * application frame, and every laundered call reads as the user's own code and
 * is allowed unconditionally — reproduced reading `/etc/passwd` under enforce
 * with a deny-by-default policy. Setting `stackTraceLimit = 0` instead blinds
 * the capture (a weaker attack: the call then reads as `unknown` and is held to
 * the default bucket, not trusted). So for the duration of the capture — and
 * only that — we force V8's own default formatter and a sane frame budget, then
 * restore the dependency's values so its legitimate error handling (source
 * maps, error monitors) is untouched. The set/restore is guarded: a dependency
 * that has frozen these as non-configurable cannot be neutralised, but that is
 * a far narrower and more conspicuous move than a plain assignment.
 */
export function captureStack(): string {
  const capture = Error.captureStackTrace as
    ((target: object, ctor?: (...args: never[]) => unknown) => void) | undefined;

  // Typed loosely: we deliberately set `prepareStackTrace` to `undefined` (the
  // signal for V8's default formatter), which its declared type forbids.
  const errorGlobal = Error as unknown as {
    prepareStackTrace?: unknown;
    stackTraceLimit?: number | undefined;
  };
  const savedPrepare = errorGlobal.prepareStackTrace;
  const savedLimit = errorGlobal.stackTraceLimit;
  try {
    errorGlobal.prepareStackTrace = undefined;
  } catch {
    // Frozen by a dependency — best effort; fall through with what's there.
  }
  if (typeof savedLimit !== 'number' || savedLimit < STACK_CAPTURE_LIMIT) {
    try {
      errorGlobal.stackTraceLimit = STACK_CAPTURE_LIMIT;
    } catch {
      // Frozen — same.
    }
  }
  try {
    if (typeof capture === 'function') {
      const holder: { stack?: string } = {};
      capture(holder, captureStack);
      return holder.stack ?? '';
    }
    return new Error().stack ?? '';
  } finally {
    try {
      errorGlobal.prepareStackTrace = savedPrepare;
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

/** Emit a record for a capability and return the decision. */
export function report(
  record: RecordFn,
  capability: Capability,
  detail: string,
): Decision {
  return record({ capability, detail, rawStack: captureStack() });
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
  const capture = Error.captureStackTrace as
    ((target: object, ctor?: (...args: never[]) => unknown) => void) | undefined;
  let stack: string;
  if (typeof capture === 'function') {
    const holder: { stack?: string } = {};
    capture(holder, boundary);
    stack = holder.stack ?? '';
  } else {
    stack = new Error().stack ?? '';
  }
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
