import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { EnvInterceptor } from '../../../src/adapters/interceptors/env.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;

beforeEach(() => {
  process.env['NPM_TOKEN'] = 'super-secret';
  process.env['NODE_ENV'] = 'test';
});
afterEach(() => {
  installed?.dispose();
  installed = undefined;
  delete process.env['NPM_TOKEN'];
});

describe('EnvInterceptor', () => {
  it('catches reads of secret-looking env vars', () => {
    const spy = recordSpy();
    spy.deny('no secrets');
    installed = new EnvInterceptor().install(spy.record);

    expect(() => process.env['NPM_TOKEN']).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('env.read');
    expect(spy.last?.detail).toBe('NPM_TOKEN');
  });

  it('does NOT flag mundane env vars', () => {
    const spy = recordSpy();
    installed = new EnvInterceptor().install(spy.record);

    expect(process.env['NODE_ENV']).toBe('test');
    expect(spy.calls).toHaveLength(0);
  });

  it('returns the value when the read is allowed', () => {
    const spy = recordSpy(); // allow
    installed = new EnvInterceptor().install(spy.record);

    expect(process.env['NPM_TOKEN']).toBe('super-secret');
    expect(spy.calls).toHaveLength(1);
  });

  it('restores process.env on dispose', () => {
    const before = process.env;
    const local = new EnvInterceptor().install(recordSpy().record);
    expect(process.env).not.toBe(before);
    local.dispose();
    expect(process.env).toBe(before);
  });
});
