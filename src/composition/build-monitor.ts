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
import { DeferredAttributor } from '../adapters/attribution/deferred-attributor.js';
import { CompiledAttributor } from '../adapters/attribution/compiled-attributor.js';
import { InMemorySink } from '../adapters/sink/in-memory-sink.js';
import { SystemClock } from '../adapters/clock/system-clock.js';
import { createInterceptors } from '../adapters/interceptors/index.js';
import { ConsoleReporter } from '../adapters/reporting/console-reporter.js';
import { HtmlReporter } from '../adapters/reporting/html-reporter.js';

export interface BuildMonitorOptions {
  readonly policy: Policy;
  /**
   * Paths belonging to dephawk itself, refused to every origin in every mode —
   * see {@link import('../domain/protected-path.js')}. `guard` passes its
   * shared event sink so a lifecycle script cannot erase the audit log.
   */
  readonly protectedPaths?: readonly string[];
  /**
   * URL of dephawk's register entrypoint, used to re-attach monitoring to
   * spawned children when `--import` came from the command line rather than
   * `NODE_OPTIONS`. See
   * {@link import('../adapters/interceptors/monitored-env.js')}.
   */
  readonly registerUrl?: string;
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
  const protectedPaths = options.protectedPaths ?? [];
  return new Monitor({
    policyEngine: new RulePolicyEngine(policy, protectedPaths),
    sink: options.sink ?? new InMemorySink(),
    clock: options.clock ?? new SystemClock(),
    // Innermost reads the live stack; `CompiledAttributor` overrides it while
    // `vm`-compiled code runs (the stack there names whatever the caller chose);
    // `DeferredAttributor` fills in a culprit when nothing names one at all.
    attributor:
      options.attributor ??
      new DeferredAttributor(new CompiledAttributor(new StackAttributor())),
    mode: policy.mode,
    interceptors:
      options.interceptors ??
      createInterceptors({
        protectedPaths,
        ...(options.registerUrl === undefined
          ? {}
          : { registerUrl: options.registerUrl }),
      }),
    reporters: options.reporters ?? [
      new ConsoleReporter({ mode: policy.mode }),
      new HtmlReporter(),
    ],
  });
}
