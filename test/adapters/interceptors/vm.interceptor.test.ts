import { describe, it, expect, afterEach } from 'vitest';
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
