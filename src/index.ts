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
export type { Origin } from './domain/origin.js';
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
export {
  FAILURE_THRESHOLDS,
  isFailureThreshold,
  failsThreshold,
  describeFailure,
} from './domain/failure-threshold.js';
export type { FailureThreshold } from './domain/failure-threshold.js';
export { draftPolicy } from './domain/policy-draft.js';
export type { PolicyDraft, PackageNote, DraftOptions } from './domain/policy-draft.js';
export { protectedPathAffectedBy } from './domain/protected-path.js';
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
export type { StackAttributorOptions } from './adapters/attribution/stack-attributor.js';
export {
  DeferredAttributor,
  SCHEDULED_FROM,
} from './adapters/attribution/deferred-attributor.js';
export {
  runScheduled,
  schedulingStack,
} from './adapters/attribution/scheduling-context.js';
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
  expandHome,
} from './adapters/config/normalize-policy.js';
export type { NormalizeOptions } from './adapters/config/normalize-policy.js';
export { renderConfig } from './adapters/config/render-config.js';
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
  SchedulerInterceptor,
} from './adapters/interceptors/index.js';
export type {
  FsInterceptorOptions,
  ChildProcessInterceptorOptions,
  WorkerInterceptorOptions,
  InterceptorOptions,
  MonitoringEnv,
  RestoredEnv,
  RestoredWorkerOptions,
} from './adapters/interceptors/index.js';
export {
  captureMonitoringEnv,
  restoreMonitoring,
  restoreWorkerOptions,
} from './adapters/interceptors/index.js';
export {
  ConsoleReporter,
  HtmlReporter,
  JsonlSinkReporter,
  parseSink,
  formatConsoleReport,
  renderHtmlReport,
  SarifReporter,
  renderSarifReport,
} from './adapters/reporting/index.js';
export type {
  SarifReporterOptions,
  SarifWriter,
  SarifMeta,
} from './adapters/reporting/index.js';
export { displayPackage } from './adapters/reporting/report-model.js';

// Composition
export { buildMonitor } from './composition/build-monitor.js';
export type { BuildMonitorOptions } from './composition/build-monitor.js';
