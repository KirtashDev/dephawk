import type { CapabilityRequest } from '../domain/capability-request.js';
import type { PolicyEngine } from '../domain/policy-engine.js';
import type { Mode } from '../domain/policy.js';
import { createEvent } from '../domain/event.js';
import type {
  Attributor,
  CapabilityInterceptor,
  Clock,
  Decision,
  Disposable,
  EventSink,
  InterceptedCall,
  Reporter,
} from './ports.js';

export interface MonitorDeps {
  readonly policyEngine: PolicyEngine;
  readonly sink: EventSink;
  readonly attributor: Attributor;
  readonly clock: Clock;
  /** Active mode. Only enforce mode turns a disallowed verdict into a block. */
  readonly mode: Mode;
  readonly interceptors: readonly CapabilityInterceptor[];
  readonly reporters: readonly Reporter[];
}

/**
 * The application orchestrator. Depends only on ports; contains no Node.
 *
 * Lifecycle: {@link start} installs every interceptor and wires it to
 * {@link record}; {@link record} attributes → evaluates → records → decides;
 * {@link stop} tears the interceptors down; {@link report} runs the reporters.
 */
export class Monitor {
  private readonly deps: MonitorDeps;
  private installations: readonly Disposable[] | undefined;

  constructor(deps: MonitorDeps) {
    this.deps = deps;
  }

  /** Install all interceptors. Idempotent. */
  start(): void {
    if (this.installations !== undefined) {
      return;
    }
    this.installations = this.deps.interceptors.map((interceptor) =>
      interceptor.install((call) => this.record(call)),
    );
  }

  /**
   * The heart of dephawk: attribute the call to a package, evaluate policy,
   * record the event, and return the decision the interceptor must honour.
   */
  record(call: InterceptedCall): Decision {
    const attribution = this.deps.attributor.attribute(call.rawStack);

    const request: CapabilityRequest = {
      capability: call.capability,
      package: attribution.package,
      origin: attribution.origin,
      detail: call.detail,
      stack: attribution.frames,
    };

    const verdict = this.deps.policyEngine.evaluate(request);
    const blocked = this.deps.mode === 'enforce' && !verdict.allowed;

    this.deps.sink.emit(
      createEvent({
        capability: request.capability,
        package: request.package,
        origin: request.origin,
        detail: request.detail,
        stack: request.stack,
        sensitive: verdict.sensitive,
        allowed: verdict.allowed,
        blocked,
        reason: verdict.reason,
        timestamp: this.deps.clock.now(),
      }),
    );

    if (blocked) {
      return { allow: false, reason: verdict.reason ?? 'blocked by dephawk policy' };
    }
    return { allow: true };
  }

  /** Tear down all interceptors. Idempotent. */
  stop(): void {
    if (this.installations === undefined) {
      return;
    }
    for (const installation of this.installations) {
      installation.dispose();
    }
    this.installations = undefined;
  }

  /** Run every reporter over the current event snapshot. */
  async report(): Promise<void> {
    const events = this.deps.sink.snapshot();
    for (const reporter of this.deps.reporters) {
      await reporter.report(events);
    }
  }

  /** The events recorded so far. */
  snapshot(): ReturnType<EventSink['snapshot']> {
    return this.deps.sink.snapshot();
  }
}
