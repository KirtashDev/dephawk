/**
 * The application's ports (hexagonal boundary).
 *
 * Everything the {@link import('./monitor.js').Monitor} depends on is an
 * interface declared here. Concrete Node-touching implementations live in
 * `src/adapters/**` and are wired only in the composition root. This file also
 * re-exports the core domain contracts so consumers have a single import site
 * for "all the ports", per the target architecture.
 */

import type { Capability } from '../domain/capability.js';

// Re-exported core contracts (defined in the domain to keep dependencies
// pointing inward — the domain never imports the application).
export type { CapabilityRequest } from '../domain/capability-request.js';
export type { Verdict } from '../domain/verdict.js';
export type { PolicyEngine } from '../domain/policy-engine.js';
export type { DhEvent } from '../domain/event.js';
export type { Policy, PackagePolicy, Mode } from '../domain/policy.js';

import type { DhEvent } from '../domain/event.js';
import type { Policy } from '../domain/policy.js';

/**
 * A raw, *unattributed* capability call as seen by an interceptor. The
 * interceptor knows what happened and the raw stack, but not which package is
 * responsible — attribution is the {@link Monitor}'s job.
 */
export interface InterceptedCall {
  readonly capability: Capability;
  /** Path, host, command, or env var name. */
  readonly detail: string;
  /** The full, unparsed stack trace string captured at the call site. */
  readonly rawStack: string;
}

/** The result handed back to an interceptor: allow the call, or deny it. */
export type Decision =
  | { readonly allow: true }
  | { readonly allow: false; readonly reason: string };

/** Something that can be torn down. Local definition — we don't rely on `using`. */
export interface Disposable {
  dispose(): void;
}

/** The outcome of attributing a raw stack to a package. */
export interface Attribution {
  /** The responsible package, or null for app/unknown code. */
  readonly package: string | null;
  /** The relevant stack frames, with dephawk's own frames removed. */
  readonly frames: readonly string[];
}

/**
 * Finds which package originated a call from its raw stack. Injectable, so the
 * Monitor is testable without touching real stack traces.
 */
export interface Attributor {
  attribute(rawStack: string): Attribution;
}

/** A sink for decided events. */
export interface EventSink {
  emit(event: DhEvent): void;
  snapshot(): readonly DhEvent[];
}

/** An injectable clock. No scattered `Date.now()`. */
export interface Clock {
  now(): number;
}

/**
 * An interceptor for one capability. `install` starts intercepting and returns
 * a handle to stop. The callback records the call and returns the decision the
 * interceptor must honour (throw/deny in enforce mode).
 */
export interface CapabilityInterceptor {
  readonly name: string;
  install(record: (call: InterceptedCall) => Decision): Disposable;
}

/** Presents the collected events (console, HTML, …). */
export interface Reporter {
  report(events: readonly DhEvent[]): void | Promise<void>;
}

/** Loads the effective policy from env, config file, and defaults. */
export interface PolicyLoader {
  load(): Promise<Policy>;
}
