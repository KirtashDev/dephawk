import { describe, it, expect, afterEach } from 'vitest';
import os from 'node:os';
import { OsInterceptor } from '../../../src/adapters/interceptors/os.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('OsInterceptor', () => {
  it('records host reconnaissance and lets it through when allowed', () => {
    const spy = recordSpy();
    installed = new OsInterceptor().install(spy.record);

    const name = os.hostname();
    expect(typeof name).toBe('string');
    expect(spy.last?.capability).toBe('os.info');
    expect(spy.last?.detail).toBe('os.hostname');
  });

  it('records userInfo and networkInterfaces access', () => {
    const spy = recordSpy();
    installed = new OsInterceptor().install(spy.record);

    os.networkInterfaces();
    expect(spy.last?.detail).toBe('os.networkInterfaces');
    os.userInfo();
    expect(spy.last?.detail).toBe('os.userInfo');
  });

  it('blocks when a policy denies (enforce)', () => {
    const spy = recordSpy();
    spy.deny('no recon');
    installed = new OsInterceptor().install(spy.record);
    expect(() => os.hostname()).toThrow(/dephawk: blocked/);
  });

  it('restores originals on dispose', () => {
    const before = os.hostname;
    const local = new OsInterceptor().install(recordSpy().record);
    expect(os.hostname).not.toBe(before);
    local.dispose();
    expect(os.hostname).toBe(before);
  });
});
