import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  inRuntimeInternals,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
  loadBuiltin,
} from './support.js';

const dns = loadBuiltin('node:dns');

/**
 * Every DNS entrypoint that takes a hostname (or IP, for `reverse`) as its
 * first argument. Covers the callback API, the `dns.promises` API, and the
 * `Resolver` classes — a package that constructs its own resolver to dodge the
 * module-level functions is still seen.
 */
const DNS_METHODS = [
  'lookup',
  'lookupService',
  'resolve',
  'resolve4',
  'resolve6',
  'resolveAny',
  'resolveCaa',
  'resolveCname',
  'resolveMx',
  'resolveNaptr',
  'resolveNs',
  'resolvePtr',
  'resolveSoa',
  'resolveSrv',
  'resolveTxt',
  'reverse',
] as const;

/**
 * Intercepts DNS resolution (`dns.lookup`, `dns.resolve*`, `dns.reverse`, the
 * `dns.promises` variants, and the `dns.Resolver` classes). Recorded as
 * `net.resolve` with the queried hostname as the detail, so it is gated by the
 * same per-package host allowlist as `net.connect`.
 *
 * DNS is a high-signal channel: a dependency resolving a host it never connects
 * to over HTTP is classic reconnaissance, and encoding stolen data into
 * subdomain queries (`<base32-secret>.exfil.evil.com`) is a real exfil path
 * that leaves no TCP connection for the net interceptor to see.
 *
 * `setServers` is covered separately: it takes a list of nameservers rather than
 * a hostname, so it never matched {@link DNS_METHODS} and the resolver redirect
 * went unrecorded. That is the setup half of DNS-tunnel exfiltration — node-ipc
 * (2026) gzips 90+ credential categories, splits the archive into base64 chunks
 * sized to DNS labels and ships them out over TXT queries, pointing its own
 * `dns.Resolver` at 1.1.1.1/8.8.8.8 first so host-level DNS monitoring never
 * sees the traffic. Each nameserver is reported as its own `net.resolve` with a
 * bare `host`/`host:port` detail, so the per-package connect allowlist judges
 * where the queries would actually go.
 *
 * Limitations:
 * - `http`/`https` requests resolve their host internally, so a normal outbound
 *   request may surface *both* a `net.connect` and a `net.resolve` event for the
 *   same logical action. This is intentional over-reporting — the report
 *   collapses identical rows — rather than risk missing a standalone resolve.
 * - `dns.reverse`/`dns.lookupService` take an IP, not a hostname; a bare IPv6
 *   literal does not survive the allowlist's host parser (it strips the final
 *   hextet as a port), so an allowlisted IPv6 target is not matched for those
 *   two calls. They are still recorded; only allowlist matching is affected.
 */
export class DnsInterceptor implements CapabilityInterceptor {
  readonly name = 'dns';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    // Callback API: on deny, throw synchronously.
    this.patchGroup(dns as unknown as Record<string, unknown>, record, restores, false);

    // Promise API: on deny, reject — throwing synchronously from a
    // promise-returning method breaks its contract and crashes callers that
    // only attach `.catch` (mirrors the fetch handling in net.interceptor).
    const promises = (dns as unknown as { promises?: Record<string, unknown> }).promises;
    if (promises !== undefined) {
      this.patchGroup(promises, record, restores, true);
    }

    for (const holder of [dns, promises]) {
      const Resolver = (holder as { Resolver?: unknown } | undefined)?.Resolver;
      for (const proto of resolverPrototypes(Resolver)) {
        this.patchGroup(proto, record, restores, holder === promises);
        this.patchSetServers(proto, record, restores);
      }
    }

    // `setServers` is synchronous on every surface, including `dns.promises`, so
    // it always throws on deny rather than rejecting.
    this.patchSetServers(dns as unknown as Record<string, unknown>, record, restores);
    if (promises !== undefined) {
      this.patchSetServers(promises, record, restores);
    }

    return restorer(restores);
  }

  /**
   * Patch `setServers` on one surface. Every nameserver in the list is judged on
   * its own — the argument is an array, so there is no single host to report and
   * a partial allowlist should not buy the whole list.
   */
  private patchSetServers(
    target: Record<string, unknown>,
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    const restore = patchMethod(
      target,
      'setServers',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          if (inRuntimeInternals()) {
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          }
          const servers = Array.isArray(args[0])
            ? args[0].filter((s): s is string => typeof s === 'string')
            : [];
          for (const server of servers) {
            const decision = report(record, 'net.resolve', server);
            if (!decision.allow) {
              throw blockedError(`pointing DNS resolution at ${server}`, decision.reason);
            }
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }

  private patchGroup(
    target: Record<string, unknown>,
    record: RecordFn,
    restores: (() => void)[],
    returnsPromise: boolean,
  ): void {
    for (const key of DNS_METHODS) {
      const restore = patchMethod(
        target,
        key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            // Skip lookups made by another built-in's own implementation — see
            // `inRuntimeInternals`. `server.listen(0, '127.0.0.1')` resolves its
            // bind address on the way through, which is the runtime's plumbing,
            // not a resolve the caller decided to make.
            if (inRuntimeInternals()) {
              return (original as (...a: unknown[]) => unknown).apply(this, args);
            }
            const host = firstString(args) ?? 'unknown';
            const decision = report(record, 'net.resolve', host);
            if (!decision.allow) {
              const error = blockedError(`DNS resolution of ${host}`, decision.reason);
              if (returnsPromise) {
                return Promise.reject(error);
              }
              throw error;
            }
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          },
      );
      if (restore) {
        restores.push(restore);
      }
    }
  }
}

function firstString(args: readonly unknown[]): string | undefined {
  for (const arg of args) {
    if (typeof arg === 'string') {
      return arg;
    }
  }
  return undefined;
}

/**
 * Every prototype a `Resolver` instance actually dispatches through: the
 * exported class's, plus — when it differs — the prototype of a real instance.
 *
 * On Node they are the same object. On Bun they are not: `new dns.Resolver()`
 * returns an instance of an *internal, unexported* class, so patching
 * `dns.Resolver.prototype` alone left every method of a package-built resolver
 * unwatched — `resolver.resolve4(…)` and, worse, `resolver.setServers([…])`,
 * the DNS-tunnel redirect this interceptor exists to see. One probe instance at
 * install time finds the real prototype; it is cancelled straight away.
 */
function resolverPrototypes(Resolver: unknown): Record<string, unknown>[] {
  const declared = prototypeOf(Resolver);
  if (declared === null) {
    return [];
  }
  const protos = [declared];
  try {
    const probe = new (Resolver as new () => { cancel?: () => void })();
    const actual = Object.getPrototypeOf(probe) as Record<string, unknown> | null;
    try {
      probe.cancel?.();
    } catch {
      /* nothing in flight */
    }
    if (actual !== null && actual !== declared && actual !== Object.prototype) {
      protos.push(actual);
    }
  } catch {
    // Cannot construct one here — the declared prototype is all there is.
  }
  return protos;
}
