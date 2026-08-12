import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import util from 'node:util';
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

  it('catches a secret VALUE under a mundane name (connection string)', () => {
    // DATABASE_URL is not a secret-looking *name*, but its value carries a
    // password. The read is flagged, marked value-sensitive, and its .value is
    // hidden from the descriptor too.
    process.env['DATABASE_URL'] = 'postgres://user:secretpass@db.example.com/app';
    try {
      const spy = recordSpy();
      spy.deny('no secrets');
      installed = new EnvInterceptor().install(spy.record);

      expect(() => process.env['DATABASE_URL']).toThrow(/dephawk: blocked/);
      expect(spy.last?.capability).toBe('env.read');
      expect(spy.last?.detail).toBe('DATABASE_URL');
      expect(spy.last?.valueSensitive).toBe(true);

      const descriptor = Object.getOwnPropertyDescriptor(process.env, 'DATABASE_URL');
      expect(descriptor?.value).toBeUndefined(); // hidden behind a getter
    } finally {
      delete process.env['DATABASE_URL'];
    }
  });

  it('does NOT flag a mundane URL value with no embedded credentials', () => {
    process.env['PUBLIC_URL'] = 'https://cdn.example.com/assets';
    try {
      const spy = recordSpy();
      spy.deny();
      installed = new EnvInterceptor().install(spy.record);

      expect(process.env['PUBLIC_URL']).toBe('https://cdn.example.com/assets');
      expect(spy.calls).toHaveLength(0);
    } finally {
      delete process.env['PUBLIC_URL'];
    }
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

  it('does not leak a secret through util.inspect / console.log when denied', () => {
    // `util.inspect` (and hence `console.log(process.env)`) unwraps a Proxy to
    // its target and formats the target's own values with no trap in the way.
    // With the real env as the target this dumped every secret in one call,
    // reporting and denying nothing. The decoy target holds no values, and a
    // denied dump is replaced by a placeholder.
    const spy = recordSpy();
    spy.deny('no whole-env dumps');
    installed = new EnvInterceptor().install(spy.record);

    const shown = util.inspect(process.env);
    expect(shown).not.toContain('super-secret');
    expect(shown).toContain('hidden by dephawk');
    // Nested, too: `console.log({ env: process.env })`.
    expect(util.inspect({ env: process.env })).not.toContain('super-secret');
  });

  it('judges a whole-environment dump via inspect as process.memory', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new EnvInterceptor().install(spy.record);

    util.inspect(process.env);
    expect(spy.last?.capability).toBe('process.memory');
    expect(spy.last?.detail).toContain('inspect');
  });

  it('reveals the real environment to inspect when the dump is allowed', () => {
    // Allowed callers — your own code, or a dependency with `memory: true` —
    // still get the normal, useful `console.log(process.env)` output.
    const spy = recordSpy(); // allow
    installed = new EnvInterceptor().install(spy.record);

    expect(util.inspect(process.env)).toContain('super-secret');
    expect(spy.last?.capability).toBe('process.memory');
  });

  it('does not report or break enumerating names with Object.keys', () => {
    const spy = recordSpy();
    spy.deny('would throw if the value were touched');
    installed = new EnvInterceptor().install(spy.record);

    const keys = Object.keys(process.env);
    expect(keys).toContain('NPM_TOKEN'); // the name is visible…
    expect(spy.calls).toHaveLength(0); // …but no value was read, so nothing fired
  });

  it('cannot be sealed into breaking env enumeration', () => {
    // The Proxy wraps an empty decoy target. If a dependency could make that
    // decoy non-extensible (Object.preventExtensions/freeze), `ownKeys`
    // returning the real environment's names would violate the Proxy invariant
    // and make every Object.keys/spread/console.log(process.env) throw — a DoS.
    // Like the real process.env, sealing is refused and enumeration keeps working.
    const spy = recordSpy();
    installed = new EnvInterceptor().install(spy.record);

    expect(() => Object.preventExtensions(process.env)).toThrow(TypeError);
    expect(Reflect.preventExtensions(process.env)).toBe(false);
    expect(Object.isExtensible(process.env)).toBe(true);
    expect(Object.keys(process.env)).toContain('NODE_ENV'); // still enumerable
    expect(() => ({ ...process.env })).not.toThrow();
  });

  it('mirrors the real env prototype so it cannot be fingerprinted', () => {
    // The Proxy wraps a plain-object decoy, but must not expose the decoy's
    // Object.prototype: real process.env has its own prototype (neither
    // Object.prototype nor null). A mismatch both breaks fidelity and lets a
    // dependency detect it is being monitored by testing the prototype.
    const realProto = Object.getPrototypeOf(process.env);

    const spy = recordSpy();
    installed = new EnvInterceptor().install(spy.record);

    expect(Object.getPrototypeOf(process.env)).toBe(realProto);
    expect(Object.getPrototypeOf(process.env)).not.toBe(Object.prototype);
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
