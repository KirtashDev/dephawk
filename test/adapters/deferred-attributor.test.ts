import { describe, it, expect } from 'vitest';
import {
  DeferredAttributor,
  SCHEDULED_FROM,
} from '../../src/adapters/attribution/deferred-attributor.js';
import { runScheduled } from '../../src/adapters/attribution/scheduling-context.js';
import { StackAttributor } from '../../src/adapters/attribution/stack-attributor.js';

const attributor = new DeferredAttributor(new StackAttributor({ selfRoot: null }));

/** What the stack looks like once a timer callback is actually running. */
const detached = [
  'Error',
  '    at listOnTimeout (node:internal/timers:581:17)',
  '    at process.processTimers (node:internal/timers:519:7)',
].join('\n');

const scheduledByEvil = [
  'Error',
  '    at detach (/p/node_modules/evil-pkg/index.js:4:3)',
  '    at main (/p/app.js:2:1)',
].join('\n');

describe('DeferredAttributor', () => {
  it('blames the scheduler when the live stack names nobody', () => {
    const result = runScheduled(scheduledByEvil, () => attributor.attribute(detached));

    expect(result.package).toBe('evil-pkg');
    expect(result.origin).toBe('dependency');
  });

  it('keeps both halves of the trace, separated by a marker', () => {
    const result = runScheduled(scheduledByEvil, () => attributor.attribute(detached));

    expect(result.frames).toContain(SCHEDULED_FROM);
    expect(result.frames.some((f) => f.includes('node:internal/timers'))).toBe(true);
    expect(result.frames.some((f) => f.includes('evil-pkg'))).toBe(true);
    expect(result.frames.indexOf(SCHEDULED_FROM)).toBeLessThan(
      result.frames.findIndex((f) => f.includes('evil-pkg')),
    );
  });

  it('prefers the live stack when it already names someone', () => {
    const live = '    at read (/p/node_modules/innocent/index.js:1:1)';
    const result = runScheduled(scheduledByEvil, () => attributor.attribute(live));

    expect(result.package).toBe('innocent');
    expect(result.frames).not.toContain(SCHEDULED_FROM);
  });

  it('carries the application origin through, so your own deferred calls stay yours', () => {
    const scheduledByApp = '    at main (/p/app.js:2:1)';
    const result = runScheduled(scheduledByApp, () => attributor.attribute(detached));

    expect(result.package).toBeNull();
    expect(result.origin).toBe('application');
  });

  it('stays unknown outside any scheduling context', () => {
    const result = attributor.attribute(detached);

    expect(result.origin).toBe('unknown');
    expect(result.frames).not.toContain(SCHEDULED_FROM);
  });

  it('stays unknown when the scheduling site names nobody either', () => {
    const result = runScheduled(detached, () => attributor.attribute(detached));

    expect(result.origin).toBe('unknown');
    expect(result.frames).not.toContain(SCHEDULED_FROM);
  });

  it('propagates through nested async work', async () => {
    const seen = await runScheduled(
      scheduledByEvil,
      () =>
        new Promise<string | null>((resolve) => {
          setTimeout(() => {
            queueMicrotask(() => resolve(attributor.attribute(detached).package));
          }, 0);
        }),
    );

    expect(seen).toBe('evil-pkg');
  });
});
