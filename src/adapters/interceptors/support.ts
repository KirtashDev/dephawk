import type { Decision, InterceptedCall } from '../../application/ports.js';
import type { Capability } from '../../domain/capability.js';

/** The record callback interceptors are wired to. */
export type RecordFn = (call: InterceptedCall) => Decision;

/**
 * Capture the current stack as a string, excluding this helper's own frame.
 * Uses V8's `Error.captureStackTrace` when available (fast, no Error object
 * exposed) and degrades to `new Error().stack` elsewhere (Bun/Deno).
 */
export function captureStack(): string {
  const capture = Error.captureStackTrace as
    ((target: object, ctor?: (...args: never[]) => unknown) => void) | undefined;
  if (typeof capture === 'function') {
    const holder: { stack?: string } = {};
    capture(holder, captureStack);
    return holder.stack ?? '';
  }
  return new Error().stack ?? '';
}

/** Emit a record for a capability and return the decision. */
export function report(
  record: RecordFn,
  capability: Capability,
  detail: string,
): Decision {
  return record({ capability, detail, rawStack: captureStack() });
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

/** Build a blocked-call error with a consistent, greppable prefix. */
export function blockedError(detail: string, reason: string): Error {
  return new Error(`dephawk: blocked ${detail} — ${reason}`);
}
