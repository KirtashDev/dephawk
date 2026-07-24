import { describe, it, expect, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { SocketInterceptor } from '../../../src/adapters/interceptors/socket.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
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

  it('describes an options object and an IPC path', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);

    expect(() => net.connect({ host: 'api.host', port: 80 })).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('api.host:80');

    expect(() => net.connect('/tmp/app.sock')).toThrow(/blocked/);
    expect(spy.last?.detail).toBe('/tmp/app.sock');
  });

  it('covers tls.connect', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    expect(() => tls.connect(443, 'secure.host')).toThrow(/blocked/);
    expect(spy.last?.capability).toBe('net.connect');
    expect(spy.last?.detail).toBe('secure.host:443');
  });

  it('covers UDP dgram send', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SocketInterceptor().install(spy.record);
    const socket = dgram.createSocket('udp4');
    try {
      expect(() => socket.send(Buffer.from('x'), 53, '9.9.9.9', () => {})).toThrow(
        /blocked/,
      );
      expect(spy.last?.capability).toBe('net.connect');
      expect(spy.last?.detail).toBe('9.9.9.9:53 (udp)');
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
    const before = net.connect;
    const local = new SocketInterceptor().install(recordSpy().record);
    expect(net.connect).not.toBe(before);
    local.dispose();
    expect(net.connect).toBe(before);
  });
});
