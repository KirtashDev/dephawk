import { describe, it, expect, afterEach } from 'vitest';
import inspector from 'node:inspector';
import { InspectorInterceptor } from '../../../src/adapters/interceptors/inspector.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe('InspectorInterceptor', () => {
  it('records connecting a Session as code.eval and blocks it on deny', () => {
    const spy = recordSpy();
    spy.deny('no debugger');
    installed = new InspectorInterceptor().install(spy.record);

    const session = new inspector.Session();
    // Denied before the channel opens, so no live debugger session is left.
    expect(() => session.connect()).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('inspector.Session.connect');
  });

  it('records inspector.open as code.eval and blocks it on deny', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new InspectorInterceptor().install(spy.record);

    // Denied before any port is opened.
    expect(() => inspector.open(0)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('inspector.open');
  });

  it('records then connects a real in-process session when allowed', () => {
    const spy = recordSpy(); // default: allow
    installed = new InspectorInterceptor().install(spy.record);

    const session = new inspector.Session();
    session.connect(); // in-process only, no port — safe to open and close
    session.disconnect();
    expect(spy.last?.capability).toBe('code.eval');
    expect(spy.last?.detail).toBe('inspector.Session.connect');
  });

  it('restores Session.prototype.connect on dispose', () => {
    const before = inspector.Session.prototype.connect;
    const local = new InspectorInterceptor().install(recordSpy().record);
    expect(inspector.Session.prototype.connect).not.toBe(before);
    local.dispose();
    expect(inspector.Session.prototype.connect).toBe(before);
  });
});
