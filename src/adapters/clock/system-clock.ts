import type { Clock } from '../../application/ports.js';

/** The default {@link Clock}, backed by the system wall clock. */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
}
