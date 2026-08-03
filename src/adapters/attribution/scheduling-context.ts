import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Carries the stack captured where a deferred call was *scheduled* into the
 * turn where it finally runs.
 *
 * A callback that a package schedules but does not define — `setTimeout(
 * fs.readFileSync, 0, secret)` — leaves no frame of its own on the stack when
 * the timer fires; only runtime internals remain. The scheduling site is the
 * only place the culprit is visible, so
 * {@link import('../interceptors/scheduler.interceptor.js').SchedulerInterceptor}
 * records it there and {@link import('./deferred-attributor.js').DeferredAttributor}
 * reads it back here when the live stack turns up unattributable.
 *
 * `AsyncLocalStorage` propagates through nested async work for free, so a chain
 * of deferrals keeps pointing at whoever started it.
 */
const storage = new AsyncLocalStorage<string>();

/** Run `fn` with `stack` recorded as the scheduling site of the current turn. */
export function runScheduled<T>(stack: string, fn: () => T): T {
  return storage.run(stack, fn);
}

/** The scheduling site of the current turn, or undefined outside one. */
export function schedulingStack(): string | undefined {
  return storage.getStore();
}
