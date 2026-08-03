import type { CapabilityInterceptor } from '../../application/ports.js';
import { FsInterceptor } from './fs.interceptor.js';
import { NetInterceptor } from './net.interceptor.js';
import { SocketInterceptor } from './socket.interceptor.js';
import { DnsInterceptor } from './dns.interceptor.js';
import { ChildProcessInterceptor } from './child-process.interceptor.js';
import { WorkerInterceptor } from './worker.interceptor.js';
import { NativeAddonInterceptor } from './native.interceptor.js';
import { VmInterceptor } from './vm.interceptor.js';
import { EnvInterceptor } from './env.interceptor.js';
import { OsInterceptor } from './os.interceptor.js';
import { SchedulerInterceptor } from './scheduler.interceptor.js';
import type { FsInterceptorOptions } from './fs.interceptor.js';
import type { ChildProcessInterceptorOptions } from './child-process.interceptor.js';
import type { WorkerInterceptorOptions } from './worker.interceptor.js';

export type { FsInterceptorOptions } from './fs.interceptor.js';
export type { ChildProcessInterceptorOptions } from './child-process.interceptor.js';
export type { WorkerInterceptorOptions } from './worker.interceptor.js';
export {
  captureMonitoringEnv,
  restoreMonitoring,
  restoreWorkerOptions,
} from './monitored-env.js';
export type {
  MonitoringEnv,
  RestoredEnv,
  RestoredWorkerOptions,
} from './monitored-env.js';

/** Everything {@link createInterceptors} can be told. */
export interface InterceptorOptions
  extends
    FsInterceptorOptions,
    ChildProcessInterceptorOptions,
    WorkerInterceptorOptions {}

export { FsInterceptor } from './fs.interceptor.js';
export { NetInterceptor } from './net.interceptor.js';
export { SocketInterceptor } from './socket.interceptor.js';
export { DnsInterceptor } from './dns.interceptor.js';
export { ChildProcessInterceptor } from './child-process.interceptor.js';
export { WorkerInterceptor } from './worker.interceptor.js';
export { NativeAddonInterceptor } from './native.interceptor.js';
export { VmInterceptor } from './vm.interceptor.js';
export { EnvInterceptor } from './env.interceptor.js';
export { OsInterceptor } from './os.interceptor.js';
export { SchedulerInterceptor } from './scheduler.interceptor.js';

/**
 * The default interceptor set, in install order. Adding a capability means
 * adding one class here — the Monitor and the rest of the core never change
 * (open for extension, closed for modification).
 *
 * The scheduler interceptor comes first and records no capability of its own:
 * it keeps attribution alive across async boundaries so the others can name a
 * culprit for deferred calls.
 */
export function createInterceptors(
  options: InterceptorOptions = {},
): CapabilityInterceptor[] {
  return [
    new SchedulerInterceptor(),
    new FsInterceptor(options),
    new NetInterceptor(),
    new SocketInterceptor(),
    new DnsInterceptor(),
    new ChildProcessInterceptor(options),
    new WorkerInterceptor(options),
    new NativeAddonInterceptor(),
    new VmInterceptor(),
    new EnvInterceptor(),
    new OsInterceptor(),
  ];
}
