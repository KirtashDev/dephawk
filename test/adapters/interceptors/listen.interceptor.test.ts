import { describe, it, expect, afterEach } from 'vitest';
import net from 'node:net';
import http from 'node:http';
import dgram from 'node:dgram';
import { ListenInterceptor } from '../../../src/adapters/interceptors/listen.interceptor.js';
import { DnsInterceptor } from '../../../src/adapters/interceptors/dns.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('ListenInterceptor', () => {
  it('records a net server listen as net.listen and blocks it on deny', () => {
    const spy = recordSpy();
    spy.deny('no listening');
    installed = new ListenInterceptor().install(spy.record);

    const server = net.createServer(() => {});
    // Denied before the port is bound, so nothing is left listening.
    expect(() => server.listen(0)).toThrow(/dephawk: blocked inbound listener/);
    expect(spy.last?.capability).toBe('net.listen');
    expect(spy.last?.detail).toBe(':0');
  });

  it('covers http servers via the shared net.Server.prototype.listen', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ListenInterceptor().install(spy.record);

    const server = http.createServer(() => {});
    expect(() => server.listen(8080, '127.0.0.1')).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('net.listen');
    expect(spy.last?.detail).toBe('127.0.0.1:8080');
  });

  it('records a dgram bind as net.listen', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new ListenInterceptor().install(spy.record);

    const socket = dgram.createSocket('udp4');
    expect(() => socket.bind(0)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('net.listen');
    expect(spy.last?.detail).toBe('udp::0');
    socket.close();
  });

  it('records then really binds when allowed', async () => {
    const spy = recordSpy(); // default: allow
    installed = new ListenInterceptor().install(spy.record);

    const server = net.createServer(() => {});
    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', resolve);
      server.on('error', reject);
    });
    expect(spy.last?.capability).toBe('net.listen');
    server.close();
  });

  it('does not invent a DNS resolve for the address it binds', async () => {
    // Node resolves the bind address inside `listen`. That lookup is the
    // runtime's plumbing, not a resolve the caller asked for — before the
    // runtime-internals guard, `listen(0, '127.0.0.1')` reported a bogus
    // `net.resolve` against whoever opened the server.
    const spy = recordSpy(); // allow, so the real listen (and its lookup) runs
    const dns = new DnsInterceptor().install(spy.record);
    const listen = new ListenInterceptor().install(spy.record);

    const server = net.createServer(() => {});
    try {
      await new Promise<void>((resolve, reject) => {
        server.listen(0, '127.0.0.1', resolve);
        server.on('error', reject);
      });
      expect(spy.calls.map((call) => call.capability)).toEqual(['net.listen']);
    } finally {
      server.close();
      listen.dispose();
      dns.dispose();
    }
  });

  it('restores net.Server.prototype.listen on dispose', () => {
    const before = net.Server.prototype.listen;
    const local = new ListenInterceptor().install(recordSpy().record);
    expect(net.Server.prototype.listen).not.toBe(before);
    local.dispose();
    expect(net.Server.prototype.listen).toBe(before);
  });
});
