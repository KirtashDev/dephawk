import { describe, it, expect, afterEach } from 'vitest';
import {
  isCompiledFilename,
  resetCompiledFilenames,
} from '../../../src/adapters/attribution/compiled-context.js';
import vm from 'node:vm';
import { VmInterceptor } from '../../../src/adapters/interceptors/vm.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('VmInterceptor', () => {
  it('records runInThisContext as code.eval with a source snippet, and passes through', () => {
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);

    const result = vm.runInThisContext('1 + 1');
    expect(result).toBe(2);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('1 + 1');
    // A convenience fn delegates to Script.prototype internally; the depth guard
    // must dedup so exactly one event is recorded, not two.
    expect(spy.calls).toHaveLength(1);
  });

  it('collapses whitespace and truncates long sources', () => {
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);
    vm.runInNewContext('const x =\n   1;\n x');
    expect(spy.last?.detail).toBe('const x = 1; x');
  });

  it('records compiled Script.prototype.runInThisContext', () => {
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);
    const script = new vm.Script('2 + 3');
    expect(script.runInThisContext()).toBe(5);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('<compiled vm.Script>');
  });

  it('reports a standalone Script.runInNewContext exactly once (no self double-fire)', () => {
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);
    // runInNewContext delegates to this.runInContext internally — both patched.
    const result = new vm.Script('6 * 7').runInNewContext({});
    expect(result).toBe(42);
    expect(spy.calls).toHaveLength(1);
    expect(spy.last?.detail).toBe('<compiled vm.Script>');
  });

  it('truncates a long source snippet to 80 chars with an ellipsis', () => {
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);
    vm.runInThisContext('1;'.repeat(50)); // 100 chars, valid, returns 1
    expect(spy.last?.detail).toHaveLength(80);
    expect(spy.last?.detail?.endsWith('…')).toBe(true);
    expect(spy.last?.detail?.startsWith('1;1;')).toBe(true);
  });

  it('labels a non-string source', () => {
    const spy = recordSpy();
    spy.deny('no eval'); // deny so the (invalid) source never runs
    installed = new VmInterceptor().install(spy.record);
    expect(() => vm.runInThisContext(123 as unknown as string)).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.detail).toBe('<non-string source>');
  });

  it('blocks in enforce mode before the code runs', () => {
    const spy = recordSpy();
    spy.deny('no eval');
    installed = new VmInterceptor().install(spy.record);
    // If this executed, it would throw a different error — assert the block wins.
    expect(() => vm.runInThisContext('throw new Error("ran")')).toThrow(
      /dephawk: blocked dynamic code execution/,
    );
  });

  it('restores originals on dispose', () => {
    const before = vm.runInThisContext;
    const local = new VmInterceptor().install(recordSpy().record);
    expect(vm.runInThisContext).not.toBe(before);
    local.dispose();
    expect(vm.runInThisContext).toBe(before);
  });
});

describe('VmInterceptor — recording the filename vm is told to use', () => {
  afterEach(() => {
    resetCompiledFilenames();
  });

  it('records the filename from a module-level run', () => {
    const spy = recordSpy(); // allow, so the code actually compiles
    installed = new VmInterceptor().install(spy.record);

    vm.runInThisContext('1 + 1', { filename: '/proj/node_modules/innocent/index.js' });
    expect(isCompiledFilename('/proj/node_modules/innocent/index.js:1:1')).toBe(true);
  });

  it('records the filename a vm.Script was constructed with', () => {
    // The run methods never see that option — it is given to the constructor,
    // which is why the constructor is wrapped too.
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);

    const script = new vm.Script('2 + 2', {
      filename: '/proj/node_modules/other/lib.js',
    });
    expect(isCompiledFilename('/proj/node_modules/other/lib.js:1:1')).toBe(true);
    // The subclass must still behave like a Script.
    expect(script.runInThisContext()).toBe(4);
  });

  it('records the filename a legacy vm.createScript was given', () => {
    // createScript builds a Script through the internal binding, so the Script
    // constructor subclass never sees the filename — the createScript wrapper is
    // what records it, so a forged filename cannot launder attribution.
    const createScript = (vm as unknown as { createScript?: unknown }).createScript;
    if (typeof createScript !== 'function') {
      return; // not on this runtime
    }
    const spy = recordSpy();
    installed = new VmInterceptor().install(spy.record);

    (vm as unknown as { createScript: (c: string, o: unknown) => unknown }).createScript(
      '3 + 3',
      { filename: '/proj/node_modules/legacy/lib.js' },
    );
    expect(isCompiledFilename('/proj/node_modules/legacy/lib.js:1:1')).toBe(true);
  });

  it('restores the original vm.Script on dispose', () => {
    const before = vm.Script;
    const local = new VmInterceptor().install(recordSpy().record);
    expect(vm.Script).not.toBe(before);
    local.dispose();
    expect(vm.Script).toBe(before);
  });
});
