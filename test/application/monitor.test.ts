import { describe, it, expect } from 'vitest';
import { Monitor } from '../../src/application/monitor.js';
import type { MonitorDeps } from '../../src/application/monitor.js';
import type { Verdict } from '../../src/domain/verdict.js';
import type { Mode } from '../../src/domain/policy.js';
import type { CapabilityRequest } from '../../src/domain/capability-request.js';
import type { InterceptedCall } from '../../src/application/ports.js';
import {
  FakeAttributor,
  FakeClock,
  FakeInterceptor,
  FakeReporter,
  FakeSink,
  StubPolicyEngine,
} from './doubles.js';

interface Wired {
  monitor: Monitor;
  sink: FakeSink;
  engine: StubPolicyEngine;
  interceptor: FakeInterceptor;
  reporter: FakeReporter;
}

function wire(opts: {
  mode?: Mode;
  verdict?: Verdict | ((r: CapabilityRequest) => Verdict);
  pkg?: string | null;
}): Wired {
  const sink = new FakeSink();
  const engine = new StubPolicyEngine(
    opts.verdict ?? { allowed: true, sensitive: false },
  );
  const interceptor = new FakeInterceptor('fake');
  const reporter = new FakeReporter();
  const deps: MonitorDeps = {
    policyEngine: engine,
    sink,
    attributor: new FakeAttributor({
      package: opts.pkg === undefined ? 'evil-pkg' : opts.pkg,
      frames: ['at evil-pkg (node_modules/evil-pkg/index.js:1:1)'],
    }),
    clock: new FakeClock(500),
    mode: opts.mode ?? 'observe',
    interceptors: [interceptor],
    reporters: [reporter],
  };
  return { monitor: new Monitor(deps), sink, engine, interceptor, reporter };
}

const call: InterceptedCall = {
  capability: 'net.connect',
  detail: 'https://evil.example',
  rawStack: 'Error\n  at foo',
};

describe('Monitor.record', () => {
  it('attributes, evaluates, records, and returns the decision', () => {
    const { monitor, sink, engine } = wire({
      verdict: { allowed: false, sensitive: true, reason: 'nope' },
      mode: 'observe',
    });

    const decision = monitor.record(call);

    expect(engine.seen[0]?.package).toBe('evil-pkg');
    expect(engine.seen[0]?.stack).toEqual([
      'at evil-pkg (node_modules/evil-pkg/index.js:1:1)',
    ]);
    expect(sink.events).toHaveLength(1);
    const event = sink.events[0]!;
    expect(event.capability).toBe('net.connect');
    expect(event.detail).toBe('https://evil.example');
    expect(event.allowed).toBe(false);
    expect(event.sensitive).toBe(true);
    expect(event.reason).toBe('nope');
    expect(event.timestamp).toBe(500);
    // observe mode never blocks
    expect(event.blocked).toBe(false);
    expect(decision).toEqual({ allow: true });
  });

  it('blocks a disallowed action in enforce mode', () => {
    const { monitor, sink } = wire({
      verdict: { allowed: false, sensitive: true, reason: 'not allowlisted' },
      mode: 'enforce',
    });

    const decision = monitor.record(call);

    expect(sink.events[0]!.blocked).toBe(true);
    expect(decision).toEqual({ allow: false, reason: 'not allowlisted' });
  });

  it('supplies a fallback reason when the verdict has none', () => {
    const { monitor } = wire({
      verdict: { allowed: false, sensitive: false },
      mode: 'enforce',
    });
    const decision = monitor.record(call);
    expect(decision.allow).toBe(false);
    if (!decision.allow) {
      expect(decision.reason).toBe('blocked by dephawk policy');
    }
  });

  it('allows an allowed action in enforce mode', () => {
    const { monitor, sink } = wire({
      verdict: { allowed: true, sensitive: false },
      mode: 'enforce',
    });
    const decision = monitor.record(call);
    expect(sink.events[0]!.blocked).toBe(false);
    expect(decision).toEqual({ allow: true });
  });

  it('omits reason on the event when the verdict allows', () => {
    const { monitor, sink } = wire({ verdict: { allowed: true, sensitive: false } });
    monitor.record(call);
    expect('reason' in sink.events[0]!).toBe(false);
  });
});

describe('Monitor lifecycle', () => {
  it('start installs interceptors and wires record end-to-end', () => {
    const { monitor, interceptor, sink } = wire({
      verdict: { allowed: false, sensitive: true, reason: 'x' },
      mode: 'enforce',
    });
    monitor.start();
    expect(interceptor.installed).toBe(1);
    // The interceptor now drives record through its captured callback.
    const decision = interceptor.record!(call);
    expect(decision.allow).toBe(false);
    expect(sink.events).toHaveLength(1);
  });

  it('start is idempotent', () => {
    const { monitor, interceptor } = wire({});
    monitor.start();
    monitor.start();
    expect(interceptor.installed).toBe(1);
  });

  it('stop disposes installations and is idempotent', () => {
    const { monitor, interceptor } = wire({});
    monitor.start();
    monitor.stop();
    monitor.stop();
    expect(interceptor.disposed).toBe(1);
  });

  it('stop before start is a no-op', () => {
    const { monitor, interceptor } = wire({});
    monitor.stop();
    expect(interceptor.disposed).toBe(0);
  });
});

describe('Monitor.report', () => {
  it('runs every reporter over the snapshot', async () => {
    const { monitor, reporter } = wire({});
    monitor.record(call);
    await monitor.report();
    expect(reporter.calls).toHaveLength(1);
    expect(reporter.calls[0]).toHaveLength(1);
  });

  it('snapshot exposes recorded events', () => {
    const { monitor } = wire({});
    monitor.record(call);
    expect(monitor.snapshot()).toHaveLength(1);
  });
});
