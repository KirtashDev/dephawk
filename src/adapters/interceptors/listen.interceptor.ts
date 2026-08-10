import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  asRuntimeInternals,
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
 * Intercepts inbound listeners — the gap the other network interceptors leave
 * open. `net`/`socket`/`dns` all watch egress (a dependency phoning home); none
 * watch a dependency that *binds a port and waits*, which is a reverse-shell or
 * C2 listener. Reproduced: `net.createServer().listen(0)` and
 * `http.createServer().listen(0)` bound a port under enforce mode with a
 * deny-by-default policy and produced "no monitored activity recorded".
 *
 * One patch on `net.Server.prototype.listen` covers `net`, `http`, `https`, and
 * `http2` servers, which all extend `net.Server` and inherit its `listen`. UDP
 * is covered separately at `dgram.Socket.prototype.bind`. Recorded as the new
 * `net.listen` capability with the bind target as the detail, so a package can
 * be allowlisted to listen (`net: { listen: true }`) independently of where it
 * may connect.
 *
 * Limitation: a listener opened through raw internal bindings
 * (`process.binding('tcp_wrap')`) does not pass through these prototypes — that
 * path is covered by the {@link import('./binding.interceptor.js').BindingInterceptor}
 * instead.
 */
export class ListenInterceptor implements CapabilityInterceptor {
  readonly name = 'listen';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];

    const serverProto = prototypeOf((net as unknown as { Server?: unknown }).Server);
    if (serverProto) {
      this.patch(serverProto, 'listen', describeListen, record, restores);
    }

    const socketProto = prototypeOf((dgram as unknown as { Socket?: unknown }).Socket);
    if (socketProto) {
      this.patch(socketProto, 'bind', describeBind, record, restores);
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
          const decision = report(record, 'net.listen', detail);
          if (!decision.allow) {
            throw blockedError(`inbound listener on ${detail}`, decision.reason);
          }
          // Node resolves the bind address on the way through, so
          // `listen(0, '127.0.0.1')` would otherwise surface a `net.resolve`
          // against the caller for a lookup it never asked for.
          return asRuntimeInternals(() =>
            (original as (...a: unknown[]) => unknown).apply(this, args),
          );
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }
}

/** Describe a `server.listen(...)` bind target from its polymorphic args. */
function describeListen(args: readonly unknown[]): string {
  const first = args[0];
  if (typeof first === 'number') {
    const host = args.slice(1).find((a): a is string => typeof a === 'string');
    return host === undefined ? `:${first}` : `${host}:${first}`;
  }
  if (typeof first === 'string') {
    return first; // IPC pipe / unix socket path
  }
  if (isObject(first)) {
    if (typeof first['path'] === 'string') {
      return first['path'];
    }
    const host = asString(first['host']) ?? '';
    const port = first['port'];
    if (port === undefined) {
      return host === '' ? '<handle>' : host;
    }
    return `${host}:${String(port)}`;
  }
  return '<handle>';
}

/** Describe a `dgram.Socket.bind(...)` target as a `udp:` listener. */
function describeBind(args: readonly unknown[]): string {
  const first = args[0];
  if (typeof first === 'number') {
    const address = args.slice(1).find((a): a is string => typeof a === 'string');
    return address === undefined ? `udp::${first}` : `udp:${address}:${first}`;
  }
  if (isObject(first)) {
    const address = asString(first['address']) ?? '';
    const port = first['port'];
    return port === undefined ? `udp:${address}` : `udp:${address}:${String(port)}`;
  }
  return 'udp'; // bind() with no argument: OS-assigned ephemeral port
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
