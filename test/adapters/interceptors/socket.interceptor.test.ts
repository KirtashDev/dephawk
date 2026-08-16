import { describe, it, expect, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { SocketInterceptor } from '../../../src/adapters/interceptors/socket.interceptor.js';
import type {
  Decision,
  Disposable,
  InterceptedCall,
} from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('SocketInterceptor', () => {
  it('records net.connect(port, host) as host:port', () => {
    const spy = recordSpy();
    spy.deny('not allowlisted');
    installed = new SocketInterceptor().install(spy.record);
    expect(() => net.connect(9999, 'evil.example.com')).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('net.connect');
    expect(spy.last?.detail).toBe('evil.example.com:9999');
  });

  it('describes an options object, an IPC path, a bare-host option and a port-less path option', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);

    expect(() => net.connect({ host: 'api.host', port: 80 })).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('api.host:80');

    expect(() => net.connect('/tmp/app.sock')).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('/tmp/app.sock');

    // options with a `path` (IPC) and options with a host but no port.
    expect(() => net.connect({ path: '/tmp/ipc.sock' })).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('/tmp/ipc.sock');

    // host without port is not a valid TcpNetConnectOpts to TS, but the
    // describer must still handle it — exercise the runtime branch via a cast.
    expect(() =>
      net.connect({ host: 'no-port.host' } as unknown as net.NetConnectOpts),
    ).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('no-port.host');
  });

  it('covers tls.connect (it delegates to Socket.prototype.connect)', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    expect(() => tls.connect(443, 'secure.host')).toThrow(/blocked/);
    expect(spy.last?.capability).toBe('net.connect');
    expect(spy.last?.detail).toBe('secure.host:443');
  });

  it('covers a bare new net.Socket().connect() to an IP — the raw-egress gap', () => {
    const spy = recordSpy();
    spy.deny('no raw egress');
    installed = new SocketInterceptor().install(spy.record);

    const socket = new net.Socket();
    // A hardcoded IP means no DNS lookup to catch it in passing: the connect
    // itself must be seen. Denied before the handshake, so nothing is dialed.
    expect(() => socket.connect(4444, '93.184.216.34')).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('net.connect');
    expect(spy.last?.detail).toBe('93.184.216.34:4444');
    socket.destroy();
  });

  it('covers Socket.prototype.connect with an options object', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);

    const socket = new net.Socket();
    expect(() => socket.connect({ port: 4444, host: '10.0.0.5' })).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('10.0.0.5:4444');
    socket.destroy();
  });

  it('covers UDP dgram send with a parseable udp:// detail', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    const socket = dgram.createSocket('udp4');
    try {
      expect(() => socket.send(Buffer.from('x'), 53, '9.9.9.9', () => {})).toThrow(
        /blocked/,
      );
      expect(spy.last?.capability).toBe('net.connect');
      expect(spy.last?.detail).toBe('udp://9.9.9.9:53');
    } finally {
      socket.close();
    }
  });

  it('does not mistake dgram offset/length for the port', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    const socket = dgram.createSocket('udp4');
    const buf = Buffer.from('payload');
    try {
      // send(msg, offset, length, port, address, cb) — offset 0 / length must
      // not be picked as the port.
      expect(() =>
        socket.send(buf, 0, buf.length, 8125, 'metrics.host', () => {}),
      ).toThrow(/blocked/);
      expect(spy.last?.detail).toBe('udp://metrics.host:8125');
    } finally {
      socket.close();
    }
  });

  it('covers UDP dgram connect', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    const socket = dgram.createSocket('udp4');
    try {
      expect(() => socket.connect(4433, 'c2.host', () => {})).toThrow(/blocked/);
      expect(spy.last?.capability).toBe('net.connect');
      expect(spy.last?.detail).toBe('udp://c2.host:4433');
    } finally {
      socket.close();
    }
  });

  it('passes a real connection through when allowed', async () => {
    installed = new SocketInterceptor().install(recordSpy().record);
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    await new Promise<void>((resolve, reject) => {
      const socket = net.connect(port, '127.0.0.1', () => {
        socket.end();
        resolve();
      });
      socket.on('error', reject);
    });

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('restores originals on dispose', () => {
    const before = net.Socket.prototype.connect;
    const local = new SocketInterceptor().install(recordSpy().record);
    expect(net.Socket.prototype.connect).not.toBe(before);
    local.dispose();
    expect(net.Socket.prototype.connect).toBe(before);
  });

  // A dependency-supplied `lookup` can point an allowlisted public host at an
  // internal / metadata IP — the connect passes the host allowlist while the
  // socket actually reaches the internal address.
  const dialWithLookup = async (
    record: (call: InterceptedCall) => Decision,
    address: string,
  ): Promise<Error | undefined> => {
    installed = new SocketInterceptor().install(record);
    return new Promise<Error | undefined>((resolve) => {
      const socket = net.connect({
        host: 'api.example.com',
        port: 9,
        lookup: (_h, _o, cb) =>
          (cb as (e: unknown, a: unknown) => void)(null, [{ address, family: 4 }]),
      });
      socket.on('error', (e) => {
        socket.destroy();
        resolve(e);
      });
      socket.on('connect', () => {
        socket.destroy();
        resolve(undefined);
      });
      setTimeout(() => {
        socket.destroy();
        resolve(undefined);
      }, 500);
    });
  };

  it('blocks a lookup that redirects an allowlisted host to an internal address', async () => {
    const calls: InterceptedCall[] = [];
    // Allow the declared host; refuse the internal metadata IP.
    const record = (call: InterceptedCall): Decision => {
      calls.push(call);
      return call.detail === '169.254.169.254'
        ? { allow: false, reason: 'ssrf' }
        : { allow: true };
    };
    const err = await dialWithLookup(record, '169.254.169.254');

    // The real destination was reported, not just the innocent hostname…
    expect(calls.some((c) => c.detail === '169.254.169.254')).toBe(true);
    // …and the resolution was failed, so the socket never connected.
    expect(err?.message).toMatch(/redirected to internal|dephawk: blocked/);
  });

  it('leaves a lookup that resolves to a public address alone', async () => {
    const calls: InterceptedCall[] = [];
    const record = (call: InterceptedCall): Decision => {
      calls.push(call);
      return { allow: true };
    };
    await dialWithLookup(record, '93.184.216.34');

    // Only the declared host is reported; the public resolved IP is not re-judged.
    expect(calls.every((c) => c.detail !== '93.184.216.34')).toBe(true);
  });
});
