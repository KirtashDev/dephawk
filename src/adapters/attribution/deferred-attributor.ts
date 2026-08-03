import type { Attribution, Attributor } from '../../application/ports.js';
import { StackAttributor } from './stack-attributor.js';
import { schedulingStack } from './scheduling-context.js';

/** Separates the live stack from the scheduling stack in a joined trace. */
export const SCHEDULED_FROM = '--- scheduled from ---';

/**
 * An {@link Attributor} that falls back to the *scheduling* stack when the live
 * one names nobody.
 *
 * Deferring a call through a callback the package did not write —
 * `setTimeout(fs.readFileSync, 0, secret)`, `.then(fs.readFileSync)` — erases
 * the culprit from the stack that exists when the call finally happens. The
 * {@link import('../interceptors/scheduler.interceptor.js').SchedulerInterceptor}
 * captures the stack at the scheduling site instead, and this decorator uses it
 * whenever the inner attributor comes back `unknown`.
 *
 * Only `unknown` is overridden: a live stack that names a dependency or the
 * application already identifies the immediate caller, which is the more
 * specific answer. The reported frames keep both halves, separated by
 * {@link SCHEDULED_FROM}, so the report shows where the call was armed as well
 * as where it went off.
 */
export class DeferredAttributor implements Attributor {
  private readonly inner: Attributor;

  constructor(inner: Attributor = new StackAttributor()) {
    this.inner = inner;
  }

  attribute(rawStack: string): Attribution {
    const direct = this.inner.attribute(rawStack);
    if (direct.origin !== 'unknown') {
      return direct;
    }

    const scheduled = schedulingStack();
    if (scheduled === undefined) {
      return direct;
    }

    const deferred = this.inner.attribute(scheduled);
    if (deferred.origin === 'unknown') {
      return direct; // the scheduling site names nobody either
    }

    return {
      package: deferred.package,
      origin: deferred.origin,
      frames: [...direct.frames, SCHEDULED_FROM, ...deferred.frames],
    };
  }
}
