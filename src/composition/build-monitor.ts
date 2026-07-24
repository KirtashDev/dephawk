import type { Policy } from '../domain/policy.js';
import { RulePolicyEngine } from '../domain/policy-engine.js';
import { Monitor } from '../application/monitor.js';
import type {
  Attributor,
  CapabilityInterceptor,
  Clock,
  EventSink,
  Reporter,
} from '../application/ports.js';
import { StackAttributor } from '../adapters/attribution/stack-attributor.js';
import { InMemorySink } from '../adapters/sink/in-memory-sink.js';
import { SystemClock } from '../adapters/clock/system-clock.js';
import { createInterceptors } from '../adapters/interceptors/index.js';
import { ConsoleReporter } from '../adapters/reporting/console-reporter.js';
import { HtmlReporter } from '../adapters/reporting/html-reporter.js';

export interface BuildMonitorOptions {
  readonly policy: Policy;
  /** Defaults to the full interceptor set. */
  readonly interceptors?: readonly CapabilityInterceptor[];
  /** Defaults to console + HTML reporters. */
  readonly reporters?: readonly Reporter[];
  readonly sink?: EventSink;
  readonly clock?: Clock;
  readonly attributor?: Attributor;
}

/**
 * The single composition root. Wires the domain policy engine, the base
 * adapters, the interceptors, and the reporters into a {@link Monitor}. This is
 * the only place concrete implementations meet — everything else depends on
 * ports. Every dependency is overridable, so tests can compose a Monitor from
 * fakes without patching globals.
 */
export function buildMonitor(options: BuildMonitorOptions): Monitor {
  const { policy } = options;
  return new Monitor({
    policyEngine: new RulePolicyEngine(policy),
    sink: options.sink ?? new InMemorySink(),
    clock: options.clock ?? new SystemClock(),
    attributor: options.attributor ?? new StackAttributor(),
    mode: policy.mode,
    interceptors: options.interceptors ?? createInterceptors(),
    reporters: options.reporters ?? [new ConsoleReporter(), new HtmlReporter()],
  });
}
