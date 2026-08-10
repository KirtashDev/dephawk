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

  it('does not leak a secret through getOwnPropertyDescriptor().value', () => {
    const spy = recordSpy(); // allow — we assert the value is not in the descriptor
    installed = new EnvInterceptor().install(spy.record);

    const descriptor = Object.getOwnPropertyDescriptor(process.env, 'NPM_TOKEN');
    // The value is behind a getter, not a data field, so reading .value leaks
    // nothing and reports nothing.
    expect(descriptor?.value).toBeUndefined();
    expect(typeof descriptor?.get).toBe('function');
    expect(spy.calls).toHaveLength(0);
  });

  it('reports (and can block) when the descriptor getter is actually invoked', () => {
    const spy = recordSpy();
    spy.deny('no secrets');
    installed = new EnvInterceptor().install(spy.record);

    const descriptor = Object.getOwnPropertyDescriptor(process.env, 'NPM_TOKEN');
    expect(() => descriptor?.get?.()).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('NPM_TOKEN');
  });

  it('does not report or break enumerating names with Object.keys', () => {
    const spy = recordSpy();
    spy.deny('would throw if the value were touched');
    installed = new EnvInterceptor().install(spy.record);

    const keys = Object.keys(process.env);
    expect(keys).toContain('NPM_TOKEN'); // the name is visible…
    expect(spy.calls).toHaveLength(0); // …but no value was read, so nothing fired
  });

  it('restores process.env on dispose', () => {
    const before = process.env;
    const local = new EnvInterceptor().install(recordSpy().record);
    expect(process.env).not.toBe(before);
    local.dispose();
    expect(process.env).toBe(before);
  });
});

describe('EnvInterceptor — writing through the proxy', () => {
  it('overwrites an existing variable without throwing', () => {
    // The exact shape of the bug, and why only *overwriting* triggers it:
    // creating a new property goes through CreateDataProperty, which builds a
    // full descriptor that `process.env` accepts. Overwriting an existing one
    // re-enters as `[[DefineOwnProperty]]` with a **value-only** descriptor,
    // which Node refuses — `'process.env' only accepts a configurable,
    // writable, and enumerable data descriptor`. npm assigns `env.HOME`, which
    // always already exists, so it died on every run.
    process.env['DEPHAWK_WRITE_PROBE'] = 'first';

    const spy = recordSpy();
    installed = new EnvInterceptor().install(spy.record);

    expect(() => {
      process.env['DEPHAWK_WRITE_PROBE'] = 'second';
    }).not.toThrow();
    expect(process.env['DEPHAWK_WRITE_PROBE']).toBe('second');

    installed.dispose();
    installed = undefined;
    // It landed on the real object, not on a proxy-local shadow.
    expect(process.env['DEPHAWK_WRITE_PROBE']).toBe('second');
    delete process.env['DEPHAWK_WRITE_PROBE'];
  });

  it('coerces like the real process.env does', () => {
    const spy = recordSpy();
    installed = new EnvInterceptor().install(spy.record);
    (process.env as Record<string, unknown>)['DEPHAWK_NUM_PROBE'] = 42;
    expect(process.env['DEPHAWK_NUM_PROBE']).toBe('42');
    delete process.env['DEPHAWK_NUM_PROBE'];
  });
});
