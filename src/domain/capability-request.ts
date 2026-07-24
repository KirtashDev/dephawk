import type { Capability } from './capability.js';

/**
 * An attempt by some code to exercise a sensitive capability.
 *
 * This is the pivot value object between adapters and the core: an interceptor
 * produces one, the {@link import('./policy-engine.js').PolicyEngine} evaluates
 * it, and the application turns it into a {@link import('./event.js').DhEvent}.
 * It is pure data and never references Node types.
 */
export interface CapabilityRequest {
  readonly capability: Capability;
  /** Attributed package, or null for app/unknown code. */
  readonly package: string | null;
  /** Path, host, command, or env var name — the subject of the action. */
  readonly detail: string;
  /** Attributed stack frames (dephawk frames already stripped). */
  readonly stack: readonly string[];
}
