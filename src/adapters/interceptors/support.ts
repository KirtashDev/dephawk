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
