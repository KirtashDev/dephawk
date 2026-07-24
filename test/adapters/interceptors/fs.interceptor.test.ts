import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import { resolve } from 'node:path';
import { FsInterceptor } from '../../../src/adapters/interceptors/fs.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

const FAKE_SSH = '/home/nobody/.ssh/id_rsa_dephawk_fake';

describe('FsInterceptor', () => {
  it('catches a read of a sensitive path and attributes the capability', () => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.readFileSync(FAKE_SSH)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('does NOT flag reads of ordinary files', () => {
    const spy = recordSpy();
    installed = new FsInterceptor().install(spy.record);

    // Reading the project's own package.json is mundane -> not intercepted.
    const content = fs.readFileSync(resolve('package.json'), 'utf8');
    expect(content).toContain('"name": "dephawk"');
    expect(spy.calls).toHaveLength(0);
  });

  it('records but allows a sensitive read when policy permits (observe/allow)', () => {
    const spy = recordSpy(); // default: allow
    installed = new FsInterceptor().install(spy.record);

    // Allowed -> original runs; the fake path does not exist, so the ORIGINAL
    // throws ENOENT (not a dephawk block). The call is still recorded.
    expect(() => fs.readFileSync(FAKE_SSH)).toThrow(/ENOENT/);
    // readFileSync may delegate to the (also patched) openSync internally, so
    // the same logical read can surface more than once — at least one records.
    expect(spy.calls.length).toBeGreaterThanOrEqual(1);
    expect(spy.calls.every((c) => c.capability === 'fs.read')).toBe(true);
  });

  it('catches sensitive writes as fs.write', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.writeFileSync('/home/nobody/.npmrc', 'x')).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('fs.write');
  });

  it('restores the original methods on dispose', () => {
    const before = fs.readFileSync;
    const local = new FsInterceptor().install(recordSpy().record);
    expect(fs.readFileSync).not.toBe(before);
    local.dispose();
    expect(fs.readFileSync).toBe(before);
  });
});
