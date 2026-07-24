import { isSensitiveEnv } from '../../domain/sensitivity.js';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { blockedError, report, type RecordFn } from './support.js';

/**
 * Intercepts reads of secret-looking environment variables via a Proxy over
 * `process.env`.
 *
 * Only variables whose name matches the secret pattern are inspected — mundane
 * reads (NODE_ENV, PATH, …) pass straight through with no stack capture, which
 * keeps overhead negligible on the hot path. In enforce mode a disallowed read
 * throws before the value is returned.
 *
 * Limitation: code that destructures `process.env` at module-load time reads
 * the value once and escapes later interception. This is best-effort by design.
 */
export class EnvInterceptor implements CapabilityInterceptor {
  readonly name = 'env';

  install(record: RecordFn): Disposable {
    const original = process.env;

    const proxy = new Proxy(original, {
      get(target, prop, receiver): unknown {
        if (typeof prop === 'string' && isSensitiveEnv(prop)) {
          const decision = report(record, 'env.read', prop);
          if (!decision.allow) {
            throw blockedError(`env read of ${prop}`, decision.reason);
          }
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    define(process, 'env', proxy);
    return {
      dispose(): void {
        define(process, 'env', original);
      },
    };
  }
}

function define(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    configurable: true,
    enumerable: true,
  });
}
