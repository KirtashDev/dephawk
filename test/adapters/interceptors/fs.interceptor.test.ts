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

describe('FsInterceptor — destructive members', () => {
  // Erasing a file changes it as surely as rewriting it, and these are what an
  // attacker reaches for to remove traces.
  const cases: [string, () => unknown][] = [
    ['unlinkSync', () => fs.unlinkSync(FAKE_SSH)],
    ['rmSync', () => fs.rmSync(FAKE_SSH)],
    ['truncateSync', () => fs.truncateSync(FAKE_SSH)],
    ['renameSync', () => fs.renameSync(FAKE_SSH, '/tmp/elsewhere')],
  ];

  for (const [name, act] of cases) {
    it(`catches ${name} as fs.write`, () => {
      const spy = recordSpy();
      spy.deny();
      installed = new FsInterceptor().install(spy.record);

      expect(act).toThrow(/dephawk: blocked/);
      expect(spy.last?.capability).toBe('fs.write');
      expect(spy.last?.detail).toContain('.ssh');
    });
  }

  it('checks both paths of a rename, whichever one is sensitive', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.renameSync('/tmp/harmless-dephawk-test', FAKE_SSH)).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('records a copy as a read of the source and a write of the destination', () => {
    const spy = recordSpy(); // allow, so both arguments are reached
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.copyFileSync(FAKE_SSH, '/home/nobody/.npmrc')).toThrow(/ENOENT/);
    expect(spy.calls.map((c) => c.capability)).toEqual(['fs.read', 'fs.write']);
  });
});

describe('FsInterceptor — dephawk’s own protected paths', () => {
  const sink = '/tmp/dephawk-guard-test/events.jsonl';

  it('reports a write to a protected path even though it is not sensitive', () => {
    const spy = recordSpy();
    spy.deny('dephawk audit log');
    installed = new FsInterceptor({ protectedPaths: [sink] }).install(spy.record);

    expect(() => fs.appendFileSync(sink, 'noise')).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.write');
    expect(spy.last?.detail).toBe(sink);
  });

  it('reports an attempt to remove the directory holding it', () => {
    const spy = recordSpy();
    spy.deny('dephawk audit log');
    installed = new FsInterceptor({ protectedPaths: [sink] }).install(spy.record);

    expect(() => fs.rmSync('/tmp/dephawk-guard-test', { recursive: true })).toThrow(
      /dephawk: blocked/,
    );
  });

  it('leaves mundane paths alone when protected paths are configured', () => {
    const spy = recordSpy();
    installed = new FsInterceptor({ protectedPaths: [sink] }).install(spy.record);

    fs.readFileSync(resolve('package.json'), 'utf8');
    expect(spy.calls).toHaveLength(0);
  });
});
