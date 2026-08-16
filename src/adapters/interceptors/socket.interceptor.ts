import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { extractHost } from '../../domain/host.js';
import { isInternalTarget } from '../../domain/threat.js';
import {
  blockedError,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
  loadBuiltin,
} from './support.js';

const net = loadBuiltin('node:net');
const dgram = loadBuiltin('node:dgram');

/**
 * Intercepts raw transport-level egress that bypasses the `http`/`https`/`fetch`
 * entrypoints, at the one chokepoint they all funnel through:
 * `net.Socket.prototype.connect` (TCP, and TLS — `tls.connect` and `TLSSocket`
 * connect their underlying socket through it), plus `dgram.Socket`
 * `send`/`connect` (UDP). Recorded as `net.connect` with `host:port` as the
 * detail, so raw sockets are gated by the same per-package host allowlist as
 * HTTP.
 *
 * Patching the prototype rather than the module-level `net.connect`/
 * `net.createConnection`/`tls.connect` is deliberate: those all delegate to
 * `Socket.prototype.connect`, so this covers them *and* the case they missed —
 * `new net.Socket().connect(port, ip)`, a plain socket to a hardcoded C2 IP,
 * which was invisible while only the module functions were patched (a hostname
 * was caught by DNS in passing, but a bare IP literal was not).
 *
 * Limitation: `http`/`https` build on TCP internally, so a normal HTTP request
 * can surface both a `net.connect` from the http interceptor and another here
 * for the same action; identical rows collapse in the report. Over-reporting is
 * preferred to missing a raw socket.
 */
export class SocketInterceptor implements CapabilityInterceptor {
  readonly name = 'socket';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    // The single TCP/TLS egress chokepoint. `net.connect`, `net.createConnection`
    // and `tls.connect` all construct a socket and delegate to this, and so does
    // a bare `new net.Socket().connect(...)`.
    const streamProto = prototypeOf((net as unknown as { Socket?: unknown }).Socket);
    if (streamProto) {
      // TCP/TLS sockets resolve their host after this call and emit `lookup`, so
      // the resolved address is watched (see `watchResolved`).
      this.patch(streamProto, 'connect', describeStream, record, restores, true);
    }

    const proto = prototypeOf((dgram as unknown as { Socket?: unknown }).Socket);
    if (proto) {
      this.patch(proto, 'connect', describeDatagram, record, restores, false);
      this.patch(proto, 'send', describeDatagram, record, restores, false);
    }

    return restorer(restores);
  }

  private patch(
    target: Record<string, unknown>,
    key: string,
    describe: (args: readonly unknown[]) => string,
    record: RecordFn,
    restores: (() => void)[],
    watchResolved: boolean,
  ): void {
    const restore = patchMethod(
      target,
      key,
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const detail = describe(args);
          const decision = report(record, 'net.connect', detail);
          if (!decision.allow) {
            throw blockedError(`socket connection to ${detail}`, decision.reason);
          }
          if (watchResolved) {
            guardResolver(args, detail, record);
          }
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }
}

/**
 * Bind enforcement to the *resolved* address, not the caller's hostname. The
 * allowlist check runs on the pre-resolution host string — but the hostname→IP
 * resolution happens inside Node after this call, through a caller-supplied
 * `lookup`. A dependency can pass an allowlisted public host *and* a `lookup`
 * that returns `169.254.169.254` (or a `10.x` internal service) and reach it
 * while dephawk recorded only the innocent hostname.
 *
 * So a dependency-supplied `lookup` is wrapped: when it resolves an allowlisted
 * *public* host to an internal / metadata address, the real destination is
 * reported (so the allowlist judges *it*) and, in enforce, the resolution is
 * failed with an error — the socket never connects. A public host resolving to a
 * public IP (the normal case, incl. `cacheable-lookup`) passes through untouched,
 * so this is essentially false-positive-free. The `lookup` *event* is not used:
 * on current Node it does not reliably carry the resolved address for a custom
 * lookup. (A default-resolver DNS-rebind to an internal IP is out of scope here —
 * that is the allowlisted domain's own DNS, not a dependency-controlled surface.)
 */
function guardResolver(args: unknown[], declaredDetail: string, record: RecordFn): void {
  const container = Array.isArray(args[0]) ? (args[0] as unknown[]) : args;
  const options = container[0];
  if (!isObject(options) || typeof options['lookup'] !== 'function') {
    return;
  }
  const declaredHost = extractHost(declaredDetail);
  if (isInternalTarget(declaredHost)) {
    return; // the caller dialed an internal host outright; already gated on connect
  }
  const originalLookup = options['lookup'] as (...a: unknown[]) => unknown;
  const wrapped = function (this: unknown, ...lookupArgs: unknown[]): unknown {
    const callback = lookupArgs[lookupArgs.length - 1] as (
      err: unknown,
      ...rest: unknown[]
    ) => void;
    const head = lookupArgs.slice(0, -1);
    return originalLookup.call(
      this,
      ...head,
      (err: unknown, resolved: unknown, family: unknown): void => {
        if (err == null) {
          // `{ all: true }` yields `[{ address, family }, …]`; otherwise a single
          // address string. Check every resolved address.
          const addresses = Array.isArray(resolved)
            ? resolved.map((entry) => (isObject(entry) ? entry['address'] : entry))
            : [resolved];
          for (const address of addresses) {
            if (typeof address === 'string' && isInternalTarget(address)) {
              const decision = report(record, 'net.connect', address);
              if (!decision.allow) {
                callback(
                  blockedError(
                    `connection to ${declaredHost} redirected to internal address ${address}`,
                    decision.reason,
                  ),
                );
                return;
              }
            }
          }
        }
        callback(err, resolved, family);
      },
    );
  };
  // Swap in a clone so the caller's options object is never mutated — but mutate
  // the *element* in place, not the container: `net.connect` hands
  // `Socket.prototype.connect` a normalised array carrying a hidden marker
  // symbol, and rebuilding that array would drop it (→ `ERR_MISSING_ARGS`).
  container[0] = { ...(options as Record<string, unknown>), lookup: wrapped };
}

/** Describe a `Socket.prototype.connect` target from its polymorphic args. */
function describeStream(args: readonly unknown[]): string {
  // `net.connect`/`net.createConnection`/`tls.connect` delegate here with the
  // arguments already normalised into a single `[options, callback]` array;
  // a direct `socket.connect(...)` arrives with the raw positional args.
  const normalised = Array.isArray(args[0]) ? (args[0] as readonly unknown[]) : args;
  const first = normalised[0];
  if (typeof first === 'number') {
    const host =
      normalised.slice(1).find((a): a is string => typeof a === 'string') ?? 'localhost';
    return `${host}:${first}`;
  }
  if (typeof first === 'string') {
    return first; // IPC socket path
  }
  if (isObject(first)) {
    if (typeof first['path'] === 'string') {
      return first['path'];
    }
    const host = asString(first['host']) ?? asString(first['hostname']) ?? 'localhost';
    const port = first['port'];
    return port === undefined ? host : `${host}:${String(port)}`;
  }
  return 'unknown';
}

/**
 * Describe a UDP `dgram` `send`/`connect` target.
 *
 * Returned as a `udp://host[:port]` URL so the policy engine's `extractHost`
 * strips it to a bare host and the per-package allowlist matches exactly as it
 * does for TCP/TLS — while the `udp://` scheme still marks the protocol in the
 * report.
 *
 * Argument shapes handled (callback stripped first):
 *   connect(port[, address])
 *   send(msg[, offset, length], port, address)   // unconnected
 *   send(msg)                                     // connected — target set at connect()
 * The address is the last string arg *after position 0* (position 0 is the
 * message for `send` and the port for `connect`, never the address), which also
 * prevents a string message on a connected socket from leaking in as the host.
 * The port is the last numeric arg, so `send`'s leading offset/length do not
 * masquerade as it.
 */
function describeDatagram(args: readonly unknown[]): string {
  const positional = args.filter((a) => typeof a !== 'function');

  let address: string | undefined;
  for (let i = 1; i < positional.length; i++) {
    if (typeof positional[i] === 'string') {
      address = positional[i] as string;
    }
  }

  let port: number | undefined;
  for (const arg of positional) {
    if (typeof arg === 'number') {
      port = arg;
    }
  }

  if (address === undefined) {
    return 'udp'; // connected-socket send, or a form with no explicit target
  }
  return port === undefined ? `udp://${address}` : `udp://${address}:${port}`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
