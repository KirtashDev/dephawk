import { describe, it, expect, afterEach, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import timers from 'node:timers';
import { FsInterceptor } from '../../../src/adapters/interceptors/fs.interceptor.js';
import { SchedulerInterceptor } from '../../../src/adapters/interceptors/scheduler.interceptor.js';
import { schedulingStack } from '../../../src/adapters/attribution/scheduling-context.js';
import type { Decision, Disposable } from '../../../src/application/ports.js';

const installed: Disposable[] = [];
afterEach(() => {
  while (installed.length > 0) {
    installed.pop()?.dispose();
  }
});

/**
 * A real, readable file whose *name* trips the sensitivity heuristic. It has to
 * exist: these tests hand `fs.readFileSync` to a timer, where a thrown ENOENT
 * would surface as an uncaught exception rather than a test failure.
 */
let secretDir: string;
let secretFile: string;

beforeAll(() => {
  secretDir = mkdtempSync(join(tmpdir(), 'dephawk-scheduler-'));
  secretFile = join(secretDir, '.npmrc');
  writeFileSync(secretFile, '//registry.npmjs.org/:_authToken=not-a-real-token\n');
});

afterAll(() => {
  rmSync(secretDir, { recursive: true, force: true });
});

/**
 * Install the scheduler tracker plus the fs interceptor, and report the
 * scheduling context visible from *inside* a patched fs call. That inner
 * vantage point is exactly where attribution runs in production.
 */
function contextAtCallTime(): { readonly seen: (string | undefined)[] } {
  // One `readFileSync` can report more than once (it opens the file through
  // another patched member), so tests assert over every context seen rather
  // than a call count.
  const seen: (string | undefined)[] = [];
  const record = (): Decision => {
    seen.push(schedulingStack());
    return { allow: true };
  };
  // The scheduler interceptor records no capability of its own — it only keeps
  // attribution alive — so it takes no record callback.
  installed.push(new SchedulerInterceptor().install());
  installed.push(new FsInterceptor().install(record));
  return { seen };
}

/** Assert that at least one context was captured and all of them match. */
function expectEvery(
  seen: readonly (string | undefined)[],
  assertion: (context: string | undefined) => void,
): void {
  expect(seen.length).toBeGreaterThan(0);
  for (const context of seen) {
    assertion(context);
  }
}

describe('SchedulerInterceptor', () => {
  it('carries the scheduling stack into a detached setTimeout callback', async () => {
    const { seen } = contextAtCallTime();

    await new Promise<void>((resolve) => {
      // The attack shape: hand the intercepted built-in straight to the timer,
      // so no frame of the scheduler survives to the moment it runs.
      setTimeout(fs.readFileSync as never, 0, secretFile);
      setTimeout(resolve, 1);
    });

    expectEvery(seen, (context) => {
      expect(context).toBeTypeOf('string');
      expect(context).toContain('scheduler.interceptor.test');
    });
  });

  it('carries the scheduling stack through Promise.prototype.then', async () => {
    const { seen } = contextAtCallTime();

    await Promise.resolve(secretFile).then(fs.readFileSync as never);

    expectEvery(seen, (context) => {
      expect(context).toContain('scheduler.interceptor.test');
    });
  });

  it('carries the scheduling stack through process.nextTick', async () => {
    const { seen } = contextAtCallTime();

    await new Promise<void>((resolve) => {
      process.nextTick(fs.readFileSync as never, secretFile);
      setTimeout(resolve, 1);
    });

    expectEvery(seen, (context) => {
      expect(context).toContain('scheduler.interceptor.test');
    });
  });

  it('leaves ordinary callbacks alone — their own frames are still live', async () => {
    const { seen } = contextAtCallTime();

    await new Promise<void>((resolve) => {
      setTimeout(() => {
        fs.readFileSync(secretFile);
        resolve();
      }, 0);
    });

    expectEvery(seen, (context) => {
      expect(context).toBeUndefined();
    });
  });

  it('records no context for a synchronous call', () => {
    const { seen } = contextAtCallTime();

    fs.readFileSync(secretFile);

    expectEvery(seen, (context) => {
      expect(context).toBeUndefined();
    });
  });

  it('preserves timer semantics and return values', async () => {
    contextAtCallTime();

    const handle = setTimeout(() => undefined, 5);
    expect(typeof handle.unref).toBe('function');
    clearTimeout(handle);

    const value = await new Promise((resolve) => setTimeout(resolve, 0, 'ok'));
    expect(value).toBe('ok');
  });

  it('keeps util.promisify custom implementations on patched schedulers', () => {
    const custom = Symbol.for('nodejs.util.promisify.custom');
    const before = (timers.setTimeout as unknown as Record<symbol, unknown>)[custom];

    contextAtCallTime();

    const after = (timers.setTimeout as unknown as Record<symbol, unknown>)[custom];
    expect(after).toBe(before);
    expect(after).toBeTypeOf('function');
  });

  it('restores every scheduler on dispose', () => {
    const originalSetTimeout = globalThis.setTimeout;
    const originalThen = Promise.prototype.then;
    const originalNextTick = process.nextTick;

    contextAtCallTime();
    expect(globalThis.setTimeout).not.toBe(originalSetTimeout);
    expect(Promise.prototype.then).not.toBe(originalThen);

    while (installed.length > 0) {
      installed.pop()?.dispose();
    }

    expect(globalThis.setTimeout).toBe(originalSetTimeout);
    expect(Promise.prototype.then).toBe(originalThen);
    expect(process.nextTick).toBe(originalNextTick);
  });
});
