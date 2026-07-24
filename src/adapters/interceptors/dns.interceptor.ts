import dns from 'node:dns';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
} from './support.js';

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
 * Limitation: `http`/`https` requests resolve their host internally, so a normal
 * outbound request may surface *both* a `net.connect` and a `net.resolve` event
 * for the same logical action. This is intentional over-reporting — the report
 * collapses identical rows — rather than risk missing a standalone resolve.
 */
export class DnsInterceptor implements CapabilityInterceptor {
  readonly name = 'dns';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    this.patchGroup(dns as unknown as Record<string, unknown>, record, restores);

    const promises = (dns as unknown as { promises?: Record<string, unknown> }).promises;
    if (promises !== undefined) {
      this.patchGroup(promises, record, restores);
    }

    for (const holder of [dns, promises]) {
      const proto = prototypeOf((holder as { Resolver?: unknown } | undefined)?.Resolver);
      if (proto) {
        this.patchGroup(proto, record, restores);
      }
    }

    return restorer(restores);
  }

  private patchGroup(
    target: Record<string, unknown>,
    record: RecordFn,
    restores: (() => void)[],
  ): void {
    for (const key of DNS_METHODS) {
      const restore = patchMethod(
        target,
        key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            const host = firstString(args) ?? 'unknown';
            const decision = report(record, 'net.resolve', host);
            if (!decision.allow) {
              throw blockedError(`DNS resolution of ${host}`, decision.reason);
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
