import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
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
 * Intercepts raw transport-level egress that bypasses the `http`/`https`/`fetch`
 * entrypoints: `net.connect`/`net.createConnection` (TCP), `tls.connect`
 * (direct TLS), and `dgram.Socket` `send`/`connect` (UDP). Recorded as
 * `net.connect` with `host:port` as the detail, so raw sockets are gated by the
 * same per-package host allowlist as HTTP.
 *
 * This closes the gap the net interceptor calls out: a package that opens a
 * plain socket to a C2 endpoint — or streams data out over UDP — never touches
 * `http`, and would otherwise be invisible.
 *
 * Limitations:
 * - `http`/`https` build on TCP internally, so a normal HTTP request can
 *   surface both a `net.connect` (from the http interceptor) and another
 *   `net.connect` here for the same action; identical rows collapse in the
 *   report. Over-reporting is preferred to missing a raw socket.
 * - Only the module-level entrypoints are patched, not
 *   `net.Socket.prototype.connect`; code that news a bare `Socket` and calls
 *   `.connect()` on it directly is not covered.
 */
export class SocketInterceptor implements CapabilityInterceptor {
  readonly name = 'socket';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    for (const key of ['connect', 'createConnection'] as const) {
      this.patch(net as unknown as Record<string, unknown>, key, describeStream, record, restores);
    }
    this.patch(tls as unknown as Record<string, unknown>, 'connect', describeStream, record, restores);

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

/** Describe a `net.connect`/`tls.connect` target from its polymorphic args. */
function describeStream(args: readonly unknown[]): string {
  const first = args[0];
  if (typeof first === 'number') {
    const host = args.slice(1).find((a): a is string => typeof a === 'string') ?? 'localhost';
    return `${host}:${first}`;
  }
  if (typeof first === 'string') {
    return first; // IPC socket path
  }
  if (isObject(first)) {
    if (typeof first['path'] === 'string') {
      return first['path'];
    }
    const host =
      asString(first['host']) ?? asString(first['hostname']) ?? 'localhost';
    const port = first['port'];
    return port === undefined ? host : `${host}:${String(port)}`;
  }
  return 'unknown';
}

/**
 * Describe a UDP `send`/`connect` target. Best-effort: the address is a string
 * argument and the port a number, but `send`'s optional offset/length are also
 * numbers, so we take the last string as the host and pair it with a port only
 * when the args unambiguously provide one.
 */
function describeDatagram(args: readonly unknown[]): string {
  let host: string | undefined;
  for (const arg of args) {
    if (typeof arg === 'string') {
      host = arg; // last string wins — the address trails any message string
    }
  }
  const port = args.find((a): a is number => typeof a === 'number');
  if (host === undefined) {
    return 'udp';
  }
  return port === undefined ? `${host} (udp)` : `${host}:${port} (udp)`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
