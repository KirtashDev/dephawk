import type { CapabilityInterceptor } from '../../application/ports.js';
import { FsInterceptor } from './fs.interceptor.js';
import { NetInterceptor } from './net.interceptor.js';
import { ChildProcessInterceptor } from './child-process.interceptor.js';
import { EnvInterceptor } from './env.interceptor.js';
import { OsInterceptor } from './os.interceptor.js';

export { FsInterceptor } from './fs.interceptor.js';
export { NetInterceptor } from './net.interceptor.js';
export { ChildProcessInterceptor } from './child-process.interceptor.js';
export { EnvInterceptor } from './env.interceptor.js';
export { OsInterceptor } from './os.interceptor.js';

/**
 * The default interceptor set, in install order. Adding a capability means
 * adding one class here — the Monitor and the rest of the core never change
 * (open for extension, closed for modification).
 */
export function createInterceptors(): CapabilityInterceptor[] {
  return [
    new FsInterceptor(),
    new NetInterceptor(),
    new ChildProcessInterceptor(),
    new EnvInterceptor(),
    new OsInterceptor(),
  ];
}
