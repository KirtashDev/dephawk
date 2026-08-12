import type { Capability } from './capability.js';
import type { Origin } from './origin.js';
import { redactSecrets, stripControlChars } from './redact.js';

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
  /** Attributed package, or null when {@link origin} is not `dependency`. */
  readonly package: string | null;
  /** Who made the call: a dependency, the user's own code, or nobody known. */
  readonly origin: Origin;
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
  readonly origin: Origin;
  readonly detail: string;
  readonly stack: readonly string[];
  readonly sensitive: boolean;
  readonly allowed: boolean;
  readonly blocked: boolean;
  readonly reason?: string | undefined;
  readonly timestamp: number;
}

/**
 * Build a frozen {@link DhEvent}. `reason` is omitted when absent.
 *
 * This is the single funnel every recorded event passes through, which makes it
 * the one place to {@link redactSecrets redact} — after policy has evaluated the
 * real request, and before any reporter, sink or SARIF file sees it. A spawn's
 * detail is the whole command line, so without this a token passed as an
 * argument would be written into the report dephawk asks you to publish.
 */
export function createEvent(input: CreateEventInput): DhEvent {
  const base = {
    capability: input.capability,
    package: input.package,
    origin: input.origin,
    detail: clean(input.detail),
    stack: Object.freeze([...input.stack]),
    sensitive: input.sensitive,
    allowed: input.allowed,
    blocked: input.blocked,
    timestamp: input.timestamp,
  };
  const event: DhEvent =
    input.reason === undefined ? base : { ...base, reason: clean(input.reason) };
  return Object.freeze(event);
}

/**
 * Strip control characters, then redact secrets — the order matters, so a
 * control character cannot split a token to slip past redaction, and no escape
 * sequence or newline reaches a reporter, the drafted config, or the sink.
 */
function clean(text: string): string {
  return redactSecrets(stripControlChars(text));
}
