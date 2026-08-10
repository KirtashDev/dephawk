import { describe, it, expect, afterEach } from 'vitest';
import { WasmInterceptor } from '../../../src/adapters/interceptors/wasm.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

// `WebAssembly` is only a namespace in this tsconfig; reach the runtime value
// through globalThis so it can be used as one.
const WA = (
  globalThis as unknown as {
    WebAssembly: {
      instantiate(bytes: Uint8Array, imports?: object): Promise<unknown>;
      compile(bytes: Uint8Array): Promise<unknown>;
      Module: new (bytes: Uint8Array) => object;
      Instance: new (module: object, imports?: object) => object;
    };
  }
).WebAssembly;

// A minimal valid module exporting add(i32, i32) -> i32.
const ADD_MODULE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 7, 7, 1, 3,
  97, 100, 100, 0, 0, 10, 9, 1, 7, 0, 32, 0, 32, 1, 106, 11,
]);

describe('WasmInterceptor', () => {
  it('records WA.instantiate as code.eval and rejects on deny', async () => {
    const spy = recordSpy();
    spy.deny('no wasm');
    installed = new WasmInterceptor().install(spy.record);

    await expect(WA.instantiate(ADD_MODULE, {})).rejects.toThrow(
      /dephawk: blocked WebAssembly execution/,
    );
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('WebAssembly.instantiate');
  });

  it('records WA.compile and rejects on deny', async () => {
    const spy = recordSpy();
    spy.deny();
    installed = new WasmInterceptor().install(spy.record);

    await expect(WA.compile(ADD_MODULE)).rejects.toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('WebAssembly.compile');
  });

  it('covers the synchronous constructors (new WA.Module)', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new WasmInterceptor().install(spy.record);

    expect(() => new WA.Module(ADD_MODULE)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('new WebAssembly.Module');
  });

  it('records then really instantiates when allowed', async () => {
    const spy = recordSpy(); // default: allow
    installed = new WasmInterceptor().install(spy.record);

    const result = (await WA.instantiate(ADD_MODULE, {})) as {
      instance: { exports: { add(a: number, b: number): number } };
    };
    expect(result.instance.exports.add(2, 3)).toBe(5);
    expect(spy.last?.detail).toBe('WebAssembly.instantiate');
  });

  it('restores WA.instantiate on dispose', () => {
    const before = WA.instantiate;
    const local = new WasmInterceptor().install(recordSpy().record);
    expect(WA.instantiate).not.toBe(before);
    local.dispose();
    expect(WA.instantiate).toBe(before);
  });
});
