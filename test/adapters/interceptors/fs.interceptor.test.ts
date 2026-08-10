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

  it('catches fs.openAsBlob of a sensitive path as fs.read', async () => {
    const spy = recordSpy();
    spy.deny('no blobs');
    installed = new FsInterceptor().install(spy.record);

    const openAsBlob = (fs as unknown as { openAsBlob?: unknown }).openAsBlob;
    if (typeof openAsBlob !== 'function') {
      return; // not on this runtime
    }
    // Denied synchronously before a Blob is ever created.
    expect(() =>
      (fs as unknown as { openAsBlob: (p: string) => unknown }).openAsBlob(FAKE_SSH),
    ).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('catches watching a sensitive path as fs.read (recon over time)', () => {
    const spy = recordSpy();
    spy.deny('no watching');
    installed = new FsInterceptor().install(spy.record);

    // Denied before a real watcher is created, so nothing is left open.
    expect(() => fs.watch(FAKE_SSH, () => {})).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('does NOT flag watching an ordinary path', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new FsInterceptor().install(spy.record);

    const watcher = fs.watch(resolve('package.json'), () => {});
    watcher.close();
    expect(spy.calls).toHaveLength(0);
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

describe('FsInterceptor — recon members', () => {
  const FAKE_SSH_DIR = '/home/nobody/.ssh';

  it.each([
    ['readdirSync', () => fs.readdirSync(FAKE_SSH_DIR)],
    ['opendirSync', () => fs.opendirSync(FAKE_SSH_DIR)],
    // The promises surface is patched too. The wrapper refuses *before* calling
    // the original, so it throws synchronously rather than rejecting.
    ['promises.readdir', () => fs.promises.readdir(FAKE_SSH_DIR)],
    // Where the key really lives is content too.
    ['readlinkSync', () => fs.readlinkSync(FAKE_SSH)],
    ['promises.readlink', () => fs.promises.readlink(FAKE_SSH)],
  ])('catches %s of a sensitive path as fs.read', (_name, act) => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(act).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('does NOT flag listing an ordinary directory', () => {
    const spy = recordSpy();
    installed = new FsInterceptor().install(spy.record);

    expect(fs.readdirSync(resolve('src'))).toContain('domain');
    expect(spy.calls).toHaveLength(0);
  });

  // `glob` arrived in Node 22 and dephawk supports 20, where the member is not
  // there to patch at all — `patchMethod` skips what a runtime does not have,
  // which is the same reason dephawk degrades gracefully on Bun and Deno.
  const hasGlob = typeof (fs as { globSync?: unknown }).globSync === 'function';

  it.skipIf(!hasGlob)('catches a glob over a sensitive directory', () => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.globSync(`${FAKE_SSH_DIR}/*`)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
  });

  it.skipIf(!hasGlob)('checks every pattern in a glob list, not just the first', () => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    // A list whose entries were never resolved would be a free pass.
    expect(() => fs.globSync(['src/*.ts', `${FAKE_SSH_DIR}/*`])).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.detail).toContain('.ssh');
  });
});

describe('FsInterceptor — cp takes a whole tree in one call', () => {
  // `cp(dir, dest, { recursive: true })` is a directory exfil primitive, and it
  // does not route through the patched `copyFile`: before this it copied
  // `~/.ssh` wholesale with the report saying "nothing sensitive touched" — in
  // enforce mode.
  it.each([
    ['cpSync', () => fs.cpSync(FAKE_SSH, '/tmp/dephawk-loot', { recursive: true })],
    [
      'promises.cp',
      () => fs.promises.cp(FAKE_SSH, '/tmp/dephawk-loot', { recursive: true }),
    ],
  ])('catches %s of a sensitive path as fs.read', (_name, act) => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(act).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('records the source as a read and the destination as a write', () => {
    const spy = recordSpy(); // allow, so both arguments are reached
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.cpSync(FAKE_SSH, '/home/nobody/.npmrc')).toThrow(/ENOENT/);
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
