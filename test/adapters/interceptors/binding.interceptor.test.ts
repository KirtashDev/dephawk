import { describe, it, expect, afterEach } from 'vitest';
import { BindingInterceptor } from '../../../src/adapters/interceptors/binding.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

type Binder = (name: unknown) => unknown;

// `process.binding` is pending-deprecated and no longer in @types/node, so
// reach it through a cast.
const proc = process as unknown as {
  binding: Binder;
  _linkedBinding?: Binder;
};

describe('BindingInterceptor', () => {
  it('records process.binding as process.native with the binding name', () => {
    const spy = recordSpy();
    spy.deny('no internal bindings');
    installed = new BindingInterceptor().install(spy.record);

    expect(() => proc.binding('fs')).toThrow(
      /dephawk: blocked internal binding access process\.binding\(fs\)/,
    );
    expect(spy.last?.capability).toBe('process.native');
    expect(spy.last?.detail).toBe('process.binding(fs)');
  });

  it('also covers process._linkedBinding', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new BindingInterceptor().install(spy.record);

    const linked = proc._linkedBinding;
    if (typeof linked !== 'function') {
      return; // not exposed on this runtime — nothing to assert
    }
    expect(() => (proc._linkedBinding as Binder)('os'))
      .toThrow(/dephawk: blocked internal binding access process\._linkedBinding\(os\)/);
    expect(spy.last?.detail).toBe('process._linkedBinding(os)');
  });

  it('falls back to "unknown" when the binding name is not a string', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new BindingInterceptor().install(spy.record);

    expect(() => proc.binding(123)).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('process.binding(unknown)');
  });

  it('records then calls through to the real binding when allowed', () => {
    const spy = recordSpy(); // default: allow
    installed = new BindingInterceptor().install(spy.record);

    const binding = proc.binding('fs');
    expect(binding).toBeTypeOf('object');
    expect(spy.last?.capability).toBe('process.native');
    expect(spy.last?.detail).toBe('process.binding(fs)');
  });

  it('restores the original process.binding on dispose', () => {
    const before = proc.binding;
    const local = new BindingInterceptor().install(recordSpy().record);
    expect(proc.binding).not.toBe(before);
    local.dispose();
    expect(proc.binding).toBe(before);
  });
});
