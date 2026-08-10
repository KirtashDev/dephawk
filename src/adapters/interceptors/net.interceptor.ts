import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  report,
  restorer,
  type RecordFn,
  loadBuiltin,
} from './support.js';

const http = loadBuiltin('node:http');
const https = loadBuiltin('node:https');

/**
 * Intercepts outbound connections: `http`/`https` `request`/`get`, and global
 * `fetch`. Every connection is recorded (they are infrequent and high-signal),
 * with the target URL/host as the detail so the policy engine can allowlist it.
 *
 * Limitation: raw `net.Socket` connections and native TLS clients that bypass
 * these entrypoints are not covered; `import { request } from 'http'` named
 * bindings captured before install escape patching.
 */
export class NetInterceptor implements CapabilityInterceptor {
  readonly name = 'net';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    for (const [mod, secure] of [
      [http, false],
      [https, true],
    ] as const) {
      for (const key of ['request', 'get'] as const) {
        const restore = patchMethod(
          mod as unknown as Record<string, unknown>,
          key,
          (original) =>
            (...args: unknown[]): unknown => {
              const detail = describeHttp(args, secure);
              const decision = report(record, 'net.connect', detail);
              if (!decision.allow) {
                throw blockedError(`connection to ${detail}`, decision.reason);
              }
              return original(...args);
            },
        );
        if (restore) {
          restores.push(restore);
        }
      }
    }

    const globalObj = globalThis as { fetch?: typeof fetch };
    const originalFetch = globalObj.fetch;
    if (typeof originalFetch === 'function') {
      globalObj.fetch = ((input: unknown, init?: unknown) => {
        const detail = describeFetch(input);
        const decision = report(record, 'net.connect', detail);
        if (!decision.allow) {
          return Promise.reject(blockedError(`fetch to ${detail}`, decision.reason));
        }
        return (originalFetch as (i: unknown, n?: unknown) => Promise<Response>)(
          input,
          init,
        );
      }) as typeof fetch;
      restores.push(() => {
        globalObj.fetch = originalFetch;
      });
    }

    return restorer(restores);
  }
}

function describeHttp(args: readonly unknown[], secure: boolean): string {
  const first = args[0];
  if (typeof first === 'string') {
    return first;
  }
  if (first instanceof URL) {
    return first.href;
  }
  if (isObject(first)) {
    const proto = asString(first['protocol']) ?? (secure ? 'https:' : 'http:');
    const host = asString(first['hostname']) ?? asString(first['host']) ?? 'localhost';
    const path = asString(first['path']) ?? '/';
    return `${proto}//${host}${path}`;
  }
  return secure ? 'https://unknown' : 'http://unknown';
}

function describeFetch(input: unknown): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  if (isObject(input)) {
    const url = asString(input['url']);
    if (url !== undefined) {
      return url;
    }
  }
  return 'unknown';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
