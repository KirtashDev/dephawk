import { describe, it, expect, afterEach } from 'vitest';
import dns from 'node:dns';
import { DnsInterceptor } from '../../../src/adapters/interceptors/dns.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('DnsInterceptor', () => {
  it('records a lookup as net.resolve with the hostname as detail', async () => {
    const spy = recordSpy();
    installed = new DnsInterceptor().install(spy.record);

    // 127.0.0.1 is an IP literal: resolved locally, no network query.
    await new Promise<void>((resolve, reject) => {
      dns.lookup('127.0.0.1', (err) => (err ? reject(err) : resolve()));
    });

    expect(spy.last?.capability).toBe('net.resolve');
    expect(spy.last?.detail).toBe('127.0.0.1');
  });

  it('records resolve* variants', () => {
    const spy = recordSpy();
    spy.deny('no dns'); // deny so the real (networked) query never runs
    installed = new DnsInterceptor().install(spy.record);

    expect(() => dns.resolveTxt('evil.example.com', () => {})).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('net.resolve');
    expect(spy.last?.detail).toBe('evil.example.com');
  });

  it('blocks resolution in enforce mode before any query', () => {
    const spy = recordSpy();
    spy.deny('not allowlisted');
    installed = new DnsInterceptor().install(spy.record);
    expect(() => dns.resolve('collector.sketchy.ru', () => {})).toThrow(
      /dephawk: blocked DNS resolution of collector\.sketchy\.ru/,
    );
  });

  it('covers the dns.promises surface', async () => {
    const spy = recordSpy();
    installed = new DnsInterceptor().install(spy.record);
    await dns.promises.lookup('127.0.0.1');
    expect(spy.last?.capability).toBe('net.resolve');
    expect(spy.last?.detail).toBe('127.0.0.1');
  });

  it('sees a package that builds its own Resolver to dodge the module fns', () => {
    const spy = recordSpy();
    spy.deny('no dns');
    installed = new DnsInterceptor().install(spy.record);

    const resolver = new dns.Resolver();
    expect(() => resolver.resolve4('exfil.evil.com', () => {})).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('net.resolve');
    expect(spy.last?.detail).toBe('exfil.evil.com');
  });

  it('covers the dns.promises.Resolver class too', () => {
    const spy = recordSpy();
    spy.deny('no dns');
    installed = new DnsInterceptor().install(spy.record);

    const resolver = new dns.promises.Resolver();
    expect(() => resolver.resolve4('exfil.evil.com')).toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('exfil.evil.com');
  });

  it('restores originals on dispose', () => {
    const before = dns.lookup;
    const local = new DnsInterceptor().install(recordSpy().record);
    expect(dns.lookup).not.toBe(before);
    local.dispose();
    expect(dns.lookup).toBe(before);
  });
});
