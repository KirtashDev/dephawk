import type { Capability } from './capability.js';

/**
 * An immutable value object: one decided capability request.
 *
 * `allowed` is the mode-independent policy verdict; `blocked` records whether
 * the call was *actually* prevented (only true in enforce mode when a
 * disallowed action occurs). Keeping both lets the report say, in observe mode,
 * "this WOULD be blocked in enforce" without re-deriving policy.
 */
export interface DhEvent {
  readonly capability: Capability;
  /** Attributed package, or null for app/unknown code. */
  readonly package: string | null;
  /** Path, host, command, or env var name — the subject of the action. */
  readonly detail: string;
  /** Attributed stack frames (dephawk frames stripped). */
  readonly stack: readonly string[];
  readonly sensitive: boolean;
  readonly allowed: boolean;
  readonly blocked: boolean;
  readonly reason?: string;
  /** Epoch milliseconds from the injected clock. */
  readonly timestamp: number;
}

export interface CreateEventInput {
  readonly capability: Capability;
  readonly package: string | null;
  readonly detail: string;
  readonly stack: readonly string[];
  readonly sensitive: boolean;
  readonly allowed: boolean;
  readonly blocked: boolean;
  readonly reason?: string | undefined;
  readonly timestamp: number;
}

/** Build a frozen {@link DhEvent}. `reason` is omitted when absent. */
export function createEvent(input: CreateEventInput): DhEvent {
  const base = {
    capability: input.capability,
    package: input.package,
    detail: input.detail,
    stack: Object.freeze([...input.stack]),
    sensitive: input.sensitive,
    allowed: input.allowed,
    blocked: input.blocked,
    timestamp: input.timestamp,
  };
  const event: DhEvent =
    input.reason === undefined ? base : { ...base, reason: input.reason };
  return Object.freeze(event);
}
