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
