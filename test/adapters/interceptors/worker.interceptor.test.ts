import { describe, it, expect, afterEach } from 'vitest';
import wt from 'node:worker_threads';
import { WorkerInterceptor } from '../../../src/adapters/interceptors/worker.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('WorkerInterceptor', () => {
  it('records worker creation as process.spawn with the script path', () => {
    const spy = recordSpy();
    spy.deny('no workers'); // deny so no real thread is created
    installed = new WorkerInterceptor().install(spy.record);

    expect(() => new wt.Worker('/tmp/task.js')).toThrow(
      /dephawk: blocked worker thread \/tmp\/task\.js/,
    );
    expect(spy.last?.capability).toBe('process.spawn');
    expect(spy.last?.detail).toBe('/tmp/task.js');
  });

  it('labels inline-eval workers as <inline eval>', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new WorkerInterceptor().install(spy.record);
    expect(() => new wt.Worker('while(true){}', { eval: true })).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.detail).toBe('<inline eval>');
  });

  it('describes a URL filename via its href', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new WorkerInterceptor().install(spy.record);
    expect(() => new wt.Worker(new URL('file:///tmp/w.js'))).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('file:///tmp/w.js');
  });

  it('constructs a real worker when allowed, then can be terminated', async () => {
    const spy = recordSpy();
    installed = new WorkerInterceptor().install(spy.record);

    const worker = new wt.Worker('0;', { eval: true });
    expect(worker).toBeInstanceOf(wt.Worker);
    expect(spy.last?.capability).toBe('process.spawn');
    await worker.terminate();
  });

  it('restores the original Worker on dispose', () => {
    const before = wt.Worker;
    const local = new WorkerInterceptor().install(recordSpy().record);
    expect(wt.Worker).not.toBe(before);
    local.dispose();
    expect(wt.Worker).toBe(before);
  });
});

describe('WorkerInterceptor — monitoring cannot be declined', () => {
  // A worker inherits process.execArgv and the environment, and anything
  // inherited can be declined: `{ execArgv: [] }` ran the whole worker
  // unmonitored, and `{ env: {} }` dropped NODE_OPTIONS to the same effect. Same
  // shape of hole as the child-process one in ADR 0006, same answer — restore it
  // and say so, rather than refuse a legitimate call. The merge itself is tested
  // in monitored-env.test.ts; what matters here is that it is wired in and that
  // the report says what had to be put back.
  const monitoring = {
    env: {
      NODE_OPTIONS: '--import file:///opt/dephawk/register.js',
    } as NodeJS.ProcessEnv,
  };

  function detailFor(options?: Record<string, unknown>): string {
    const spy = recordSpy();
    spy.deny('no workers'); // deny, so no real thread is created
    installed = new WorkerInterceptor(monitoring).install(spy.record);

    const Patched = wt.Worker as unknown as new (...args: unknown[]) => object;
    const args = options === undefined ? ['/tmp/task.js'] : ['/tmp/task.js', options];
    expect(() => new Patched(...args)).toThrow(/dephawk: blocked/);
    return spy.last?.detail ?? '';
  }

  it('notes the re-attachment when execArgv was emptied', () => {
    expect(detailFor({ execArgv: [] })).toBe(
      '/tmp/task.js [dephawk re-attached: execArgv]',
    );
  });

  it('notes it when the environment was emptied', () => {
    expect(detailFor({ env: {} })).toBe(
      '/tmp/task.js [dephawk re-attached: NODE_OPTIONS]',
    );
  });

  it('says nothing when the caller already passes the import', () => {
    expect(detailFor({ execArgv: ['--import=file:///opt/dephawk/register.js'] })).toBe(
      '/tmp/task.js',
    );
  });

  it('says nothing when the caller passes no options — it inherits both', () => {
    expect(detailFor()).toBe('/tmp/task.js');
  });
});
