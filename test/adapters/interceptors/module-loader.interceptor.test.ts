import { describe, it, expect, afterEach } from 'vitest';
import { ModuleLoaderInterceptor } from '../../../src/adapters/interceptors/module-loader.interceptor.js';
import { loadBuiltin } from '../../../src/adapters/interceptors/support.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

const Module = loadBuiltin<Record<string, unknown>>('node:module');

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('ModuleLoaderInterceptor', () => {
  it('blocks reassigning Module.prototype._compile as code.eval', () => {
    // Rewriting _compile lets a dependency inject code into another package's
    // source, so the injected code runs as — and is attributed to — that
    // package. The tell is the act of hooking the loader.
    const spy = recordSpy();
    spy.deny('no loader hooks');
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const proto = Module['prototype'] as Record<string, unknown>;
    expect(() => {
      proto['_compile'] = (): void => undefined;
    }).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toContain('Module.prototype._compile');
  });

  it('blocks writing a require.extensions handler', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const extensions = Module['_extensions'] as Record<string, unknown>;
    expect(() => {
      extensions['.js'] = (): void => undefined;
    }).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toContain('require.extensions');
  });

  it('blocks module.register (the ESM loader hook)', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const register = Module['register'];
    if (typeof register !== 'function') {
      return; // not on this runtime
    }
    expect(() => (register as (h: string) => void)('./nonexistent-hook.mjs')).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toContain('module.register');
  });

  it('leaves normal reads of the hook points working', () => {
    // Node reads Module.prototype._compile through the getter to load modules;
    // the accessor must return the real function so requiring still works.
    const spy = recordSpy();
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const proto = Module['prototype'] as Record<string, unknown>;
    expect(typeof proto['_compile']).toBe('function');
    expect(spy.calls).toHaveLength(0);
  });

  it('restores the hook points on dispose', () => {
    const proto = Module['prototype'] as Record<string, unknown>;
    const before = proto['_compile'];
    const local = new ModuleLoaderInterceptor().install(recordSpy().record);
    local.dispose();
    expect(proto['_compile']).toBe(before);
    // And a plain assignment works again after dispose.
    expect(() => {
      proto['_compile'] = before;
    }).not.toThrow();
  });

  it('cannot be dodged by Object.defineProperty on _compile (the setter-skip bypass)', () => {
    // A JS setter fires only on assignment, never on defineProperty. A configurable
    // accessor could be replaced wholesale with defineProperty and never report —
    // that let a dependency rewrite the loader under --enforce. The accessor is now
    // non-configurable, so the redefinition throws and the original stays in place.
    const spy = recordSpy();
    spy.deny('no loader hooks');
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const proto = Module['prototype'] as Record<string, unknown>;
    const original = proto['_compile'];
    const injected = (): void => undefined;
    expect(() => {
      Object.defineProperty(proto, '_compile', {
        value: injected,
        configurable: true,
        writable: true,
      });
    }).toThrow();
    // The loader was not replaced — the injection never took hold.
    expect(proto['_compile']).toBe(original);
    expect(proto['_compile']).not.toBe(injected);
  });

  it('blocks replacing the whole require.extensions object (wholesale reassignment)', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ModuleLoaderInterceptor().install(spy.record);

    expect(() => {
      (Module as Record<string, unknown>)['_extensions'] = Object.create(null) as object;
    }).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toContain('require.extensions');
  });

  it('blocks a require.extensions handler installed via Object.defineProperty', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ModuleLoaderInterceptor().install(spy.record);

    const extensions = Module['_extensions'] as Record<string, unknown>;
    expect(() => {
      Object.defineProperty(extensions, '.jsx', { value: (): void => undefined });
    }).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toContain('require.extensions');
  });
});
