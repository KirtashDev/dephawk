import { describe, it, expect } from 'vitest';
import { buildMonitor } from '../../src/composition/build-monitor.js';
import { Monitor } from '../../src/application/monitor.js';
import { InMemorySink } from '../../src/adapters/sink/in-memory-sink.js';
import type { Policy } from '../../src/domain/policy.js';
import {
  FakeAttributor,
  FakeClock,
  FakeInterceptor,
  FakeReporter,
} from '../application/doubles.js';

const policy: Policy = {
  mode: 'enforce',
  default: { net: { connect: [] } },
  packages: {},
};

describe('buildMonitor', () => {
  it('returns a Monitor with sensible defaults', () => {
    const monitor = buildMonitor({ policy });
    expect(monitor).toBeInstanceOf(Monitor);
  });

  it('wires overridden collaborators end-to-end', async () => {
    const sink = new InMemorySink();
    const interceptor = new FakeInterceptor('fake');
    const reporter = new FakeReporter();

    const monitor = buildMonitor({
      policy,
      sink,
      clock: new FakeClock(1),
      attributor: new FakeAttributor({ package: 'evil', frames: ['at evil'] }),
      interceptors: [interceptor],
      reporters: [reporter],
    });

    monitor.start();
    expect(interceptor.installed).toBe(1);

    const decision = interceptor.record!({
      capability: 'net.connect',
      detail: 'https://evil.example',
      rawStack: 'Error\n at evil',
    });
    // enforce + empty allowlist -> blocked
    expect(decision.allow).toBe(false);
    expect(sink.snapshot()[0]?.package).toBe('evil');

    await monitor.report();
    expect(reporter.calls).toHaveLength(1);

    monitor.stop();
    expect(interceptor.disposed).toBe(1);
  });
});
