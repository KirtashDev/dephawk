import timers from 'node:timers';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { runScheduled } from '../attribution/scheduling-context.js';
import { captureStack, isWrapper, patchMethod, restorer, type AnyFn } from './support.js';

/** Where the callback sits in each scheduler's argument list. */
interface SchedulerSpec {
  readonly target: Record<string, unknown>;
  readonly key: string;
  readonly callbacks: readonly number[];
}

/**
 * Preserves attribution across async boundaries. Records nothing itself.
 *
 * A dependency can strip its own name off a call by scheduling an intercepted
 * built-in directly instead of calling it: `setTimeout(fs.readFileSync, 0,
 * '~/.ssh/id_rsa')`, `Promise.resolve(path).then(fs.readFileSync)`. When the
 * timer fires the stack holds only runtime internals — the culprit is long
 * gone, and before dephawk 0.3 that unattributable call was credited to "your
 * code" and allowed even under `--enforce`.
 *
 * So we intercept the schedulers themselves and, at the moment of scheduling,
 * capture the stack — which *does* name the scheduler — into an
 * {@link import('node:async_hooks').AsyncLocalStorage} context that follows the
 * callback to wherever it runs. See
 * {@link import('../attribution/deferred-attributor.js').DeferredAttributor}.
 *
 * Cost control: the stack is only captured when the callback is itself a
 * dephawk wrapper, i.e. an intercepted built-in passed by reference. Ordinary
 * scheduling — the overwhelming majority — pays one `WeakSet` lookup per
 * callback argument and nothing else. A callback the package *does* define
 * needs no help: its own frame is on the stack when it runs.
 */
export class SchedulerInterceptor implements CapabilityInterceptor {
  readonly name = 'scheduler';

  install(): Disposable {
    const restores: (() => void)[] = [];

    for (const spec of schedulerSpecs()) {
      const restore = patchMethod(
        spec.target,
        spec.key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            bindCallbacks(args, spec.callbacks);
            return Reflect.apply(original, this, args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}

/**
 * The schedulers worth covering. `Promise.prototype.then` also covers `catch`
 * and `finally`, which the spec defines in terms of `then`. `globalThis` and
 * `node:timers` hold separate property slots for the same functions, so both
 * need patching for either import style to be covered.
 */
function schedulerSpecs(): SchedulerSpec[] {
  const global = globalThis as unknown as Record<string, unknown>;
  const timerKeys = ['setTimeout', 'setInterval', 'setImmediate'];

  return [
    ...timerKeys.map((key) => ({ target: global, key, callbacks: [0] })),
    ...timerKeys.map((key) => ({
      target: timers as unknown as Record<string, unknown>,
      key,
      callbacks: [0],
    })),
    { target: global, key: 'queueMicrotask', callbacks: [0] },
    {
      target: process as unknown as Record<string, unknown>,
      key: 'nextTick',
      callbacks: [0],
    },
    {
      target: Promise.prototype as unknown as Record<string, unknown>,
      key: 'then',
      callbacks: [0, 1],
    },
  ];
}

/** Replace any intercepted built-in in `args` with a context-carrying wrapper. */
function bindCallbacks(args: unknown[], positions: readonly number[]): void {
  for (const position of positions) {
    const callback = args[position];
    if (isWrapper(callback)) {
      args[position] = carryScheduler(callback, captureStack());
    }
  }
}

function carryScheduler(callback: AnyFn, stack: string): AnyFn {
  return function (this: unknown, ...args: unknown[]): unknown {
    return runScheduled(stack, () => Reflect.apply(callback, this, args));
  };
}
