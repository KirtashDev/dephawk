import { describe, it, expect, afterEach } from 'vitest';
import {
  captureStack,
  callerLocation,
} from '../../../src/adapters/interceptors/support.js';

// These tests poke the two `Error` globals a dependency can weaponise against
// attribution. Always restore them so a failure cannot leak into other tests.
const savedPrepare = Error.prepareStackTrace;
const savedLimit = Error.stackTraceLimit;
afterEach(() => {
  Error.prepareStackTrace = savedPrepare;
  Error.stackTraceLimit = savedLimit;
});

describe('captureStack hardening', () => {
  it('ignores a hostile Error.prepareStackTrace that forges an app frame', () => {
    const forged = 'Error\n    at Object.<anonymous> (/Users/victim/app/index.js:1:1)\n';
    Error.prepareStackTrace = () => forged;

    const stack = captureStack();
    // The forged string must NOT be what we captured…
    expect(stack).not.toBe(forged);
    expect(stack).not.toContain('/Users/victim/app/index.js');
    // …and the real frames (this test file) must be present.
    expect(stack).toContain('support.test');
  });

  it('restores the dependency’s prepareStackTrace afterwards', () => {
    const hostile = (): string => 'forged';
    Error.prepareStackTrace = hostile;
    captureStack();
    expect(Error.prepareStackTrace).toBe(hostile);
  });

  it('ignores a hijacked Error.captureStackTrace', () => {
    // The sibling of the prepareStackTrace forgery: replace the function
    // dephawk itself calls, and every capture returns whatever you wrote —
    // naming an application file, which policy allows unconditionally.
    const real = Error.captureStackTrace;
    try {
      Error.captureStackTrace = ((holder: { stack?: string }) => {
        holder.stack = 'Error\n    at Object.<anonymous> (/Users/victim/app.js:1:1)\n';
      }) as typeof Error.captureStackTrace;

      const stack = captureStack();
      expect(stack).not.toContain('/Users/victim/app.js');
      expect(stack).toContain('support.test');
    } finally {
      Error.captureStackTrace = real;
    }
  });

  it('ignores a replaced Error global', () => {
    const real = globalThis.Error;
    try {
      class FakeError {
        stack = 'Error\n    at Object.<anonymous> (/Users/victim/app.js:1:1)\n';
        static captureStackTrace(holder: { stack?: string }): void {
          holder.stack = 'Error\n    at Object.<anonymous> (/Users/victim/app.js:1:1)\n';
        }
      }
      (globalThis as { Error: unknown }).Error = FakeError;

      const stack = captureStack();
      expect(stack).not.toContain('/Users/victim/app.js');
      expect(stack).toContain('support.test');
    } finally {
      (globalThis as { Error: unknown }).Error = real;
    }
  });

  it('is not blinded by Error.stackTraceLimit = 0', () => {
    Error.stackTraceLimit = 0;
    const stack = captureStack();
    // A real, multi-frame stack came back despite the zero limit.
    expect(
      stack.split('\n').filter((l) => l.trim().startsWith('at ')).length,
    ).toBeGreaterThan(1);
    // And the caller's chosen limit is restored.
    expect(Error.stackTraceLimit).toBe(0);
  });
});

describe('callerLocation', () => {
  it('reports the immediate caller of a boundary function', () => {
    function boundary(): string {
      return callerLocation(boundary);
    }
    // The caller is this test file, not `boundary` or `callerLocation`.
    expect(boundary()).toContain('support.test');
  });
});
