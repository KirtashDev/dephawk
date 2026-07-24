import { describe, it, expect, afterEach } from 'vitest';
import { NativeAddonInterceptor } from '../../../src/adapters/interceptors/native.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('NativeAddonInterceptor', () => {
  // Every assertion denies, so the real `process.dlopen` (which would map a
  // binary into the process) is never invoked.
  it('records a dlopen as process.native with the addon path', () => {
    const spy = recordSpy();
    spy.deny('no native');
    installed = new NativeAddonInterceptor().install(spy.record);

    const fakeModule = { exports: {} };
    expect(() =>
      (process.dlopen as (m: object, f: string) => void)(fakeModule, '/x/evil.node'),
    ).toThrow(/dephawk: blocked native addon load of \/x\/evil\.node/);

    expect(spy.last?.capability).toBe('process.native');
    expect(spy.last?.detail).toBe('/x/evil.node');
  });

  it('falls back to "unknown" when the filename is not a string', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new NativeAddonInterceptor().install(spy.record);

    expect(() =>
      (process.dlopen as (m: object, f: unknown) => void)({ exports: {} }, 123),
    ).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('unknown');
  });

  it('records the load then calls through to the real dlopen when allowed', () => {
    const spy = recordSpy(); // default: allow
    installed = new NativeAddonInterceptor().install(spy.record);

    // Allowed: the wrapper must invoke the original, which then throws a real
    // (non-dephawk) load error for a nonexistent addon — proving call-through.
    let error: unknown;
    try {
      (process.dlopen as (m: object, f: string) => void)(
        { exports: {} },
        '/x/does-not-exist.node',
      );
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toMatch(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('process.native');
    expect(spy.last?.detail).toBe('/x/does-not-exist.node');
    expect(spy.calls).toHaveLength(1);
  });

  it('restores the original process.dlopen on dispose', () => {
    const before = process.dlopen;
    const local = new NativeAddonInterceptor().install(recordSpy().record);
    expect(process.dlopen).not.toBe(before);
    local.dispose();
    expect(process.dlopen).toBe(before);
  });
});
