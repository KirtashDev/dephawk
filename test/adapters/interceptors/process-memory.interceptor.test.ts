import { describe, it, expect, afterEach } from 'vitest';
import v8 from 'node:v8';
import { ProcessMemoryInterceptor } from '../../../src/adapters/interceptors/process-memory.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('ProcessMemoryInterceptor', () => {
  it('blocks a diagnostic report dump as process.memory', () => {
    // getReport() returns every environment variable as an object, past the env
    // Proxy entirely.
    const spy = recordSpy();
    spy.deny('no memory dumps');
    installed = new ProcessMemoryInterceptor().install(spy.record);

    const report = (process as unknown as { report: { getReport: () => unknown } })
      .report;
    expect(() => report.getReport()).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('process.memory');
    expect(spy.last?.detail).toBe('process.report.getReport');
  });

  it('blocks a heap snapshot as process.memory', () => {
    // A heap snapshot contains every live string — where decrypted secrets sit.
    const spy = recordSpy();
    spy.deny();
    installed = new ProcessMemoryInterceptor().install(spy.record);

    expect(() => v8.getHeapSnapshot()).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('process.memory');
    expect(spy.last?.detail).toBe('v8.getHeapSnapshot');
  });

  it('blocks v8.queryObjects as process.memory (Node >=22)', () => {
    const queryObjects = (v8 as unknown as { queryObjects?: unknown }).queryObjects;
    if (typeof queryObjects !== 'function') {
      return; // not on this runtime
    }
    const spy = recordSpy();
    spy.deny();
    installed = new ProcessMemoryInterceptor().install(spy.record);

    expect(() =>
      (
        v8 as unknown as { queryObjects: (c: unknown, o: unknown) => unknown }
      ).queryObjects(Buffer, { format: 'count' }),
    ).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('process.memory');
    expect(spy.last?.detail).toBe('v8.queryObjects');
  });

  it('lets a dump through when policy allows it', () => {
    const spy = recordSpy(); // allow
    installed = new ProcessMemoryInterceptor().install(spy.record);

    const snapshot = v8.getHeapSnapshot();
    snapshot.destroy();
    expect(spy.last?.capability).toBe('process.memory');
  });

  it('restores v8.getHeapSnapshot on dispose', () => {
    const before = v8.getHeapSnapshot;
    const local = new ProcessMemoryInterceptor().install(recordSpy().record);
    expect(v8.getHeapSnapshot).not.toBe(before);
    local.dispose();
    expect(v8.getHeapSnapshot).toBe(before);
  });
});
