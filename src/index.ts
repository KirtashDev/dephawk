/**
 * dephawk public API.
 *
 * Most users never import this — they run `dephawk run …` or
 * `node --import dephawk/register`. It exists for programmatic composition:
 * build your own Monitor, plug in custom interceptors or reporters, or reuse
 * the pure domain engine.
 */

// Domain
export { CAPABILITIES, CAPABILITY_META, isCapability } from './domain/capability.js';
export type { Capability, CapabilityMeta } from './domain/capability.js';
export type { DhEvent } from './domain/event.js';
export { createEvent } from './domain/event.js';
export type {
  Policy,
  PackagePolicy,
  NetPolicy,
  FsPolicy,
  EnvPolicy,
  Mode,
} from './domain/policy.js';
export { PERMISSIVE_POLICY } from './domain/policy.js';
export type { Verdict } from './domain/verdict.js';
export type { CapabilityRequest } from './domain/capability-request.js';
export { RulePolicyEngine } from './domain/policy-engine.js';
export type { PolicyEngine } from './domain/policy-engine.js';

// Application
export { Monitor } from './application/monitor.js';
export type { MonitorDeps } from './application/monitor.js';
export type {
  Attributor,
  Attribution,
  CapabilityInterceptor,
  Clock,
  Decision,
  Disposable,
  EventSink,
  InterceptedCall,
  PolicyLoader,
  Reporter,
} from './application/ports.js';

// Adapters
export { StackAttributor } from './adapters/attribution/stack-attributor.js';
export { InMemorySink } from './adapters/sink/in-memory-sink.js';
export { SystemClock } from './adapters/clock/system-clock.js';
export {
  EnvPolicyLoader,
  FileConfigPolicyLoader,
  resolveEnvPolicy,
} from './adapters/config/policy-loader.js';
export {
  normalizePolicy,
  applyModeOverride,
} from './adapters/config/normalize-policy.js';
export {
  createInterceptors,
  FsInterceptor,
  NetInterceptor,
  SocketInterceptor,
  DnsInterceptor,
  ChildProcessInterceptor,
  WorkerInterceptor,
  NativeAddonInterceptor,
  VmInterceptor,
  EnvInterceptor,
  OsInterceptor,
} from './adapters/interceptors/index.js';
export {
  ConsoleReporter,
  HtmlReporter,
  formatConsoleReport,
  renderHtmlReport,
} from './adapters/reporting/index.js';

// Composition
export { buildMonitor } from './composition/build-monitor.js';
export type { BuildMonitorOptions } from './composition/build-monitor.js';
