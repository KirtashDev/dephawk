import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
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
      this.patch(streamProto, 'connect', describeStream, record, restores);
    }

    const proto = prototypeOf((dgram as unknown as { Socket?: unknown }).Socket);
    if (proto) {
      this.patch(proto, 'connect', describeDatagram, record, restores);
      this.patch(proto, 'send', describeDatagram, record, restores);
    }

    return restorer(restores);
  }

  private patch(
    target: Record<string, unknown>,
    key: string,
    describe: (args: readonly unknown[]) => string,
    record: RecordFn,
    restores: (() => void)[],
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
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }
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
