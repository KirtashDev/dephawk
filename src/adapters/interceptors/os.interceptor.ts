import os from 'node:os';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, patchMethod, report, restorer, type RecordFn } from './support.js';

const OS_METHODS = ['userInfo', 'networkInterfaces', 'hostname', 'homedir'] as const;

/**
 * Intercepts host/OS reconnaissance (`os.userInfo`, `os.networkInterfaces`,
 * `os.hostname`, `os.homedir`). These are recorded as `os.info`; the default
 * policy permits them (informational), but they still show up in the report as
 * a signal of a package profiling its host.
 */
export class OsInterceptor implements CapabilityInterceptor {
  readonly name = 'os';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = os as unknown as Record<string, unknown>;

    for (const key of OS_METHODS) {
      const restore = patchMethod(
        mod,
        key,
        (original) =>
          (...args: unknown[]): unknown => {
            const detail = `os.${key}`;
            const decision = report(record, 'os.info', detail);
            if (!decision.allow) {
              throw blockedError(detail, decision.reason);
            }
            return original(...args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }
}
