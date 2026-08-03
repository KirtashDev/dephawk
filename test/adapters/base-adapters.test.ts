import { describe, it, expect } from 'vitest';
import { InMemorySink } from '../../src/adapters/sink/in-memory-sink.js';
import { SystemClock } from '../../src/adapters/clock/system-clock.js';
import { createEvent } from '../../src/domain/event.js';

function anEvent(detail: string) {
  return createEvent({
    capability: 'fs.read',
    package: 'p',
    origin: 'dependency',
    detail,
    stack: [],
    sensitive: false,
    allowed: true,
    blocked: false,
    timestamp: 0,
  });
}

describe('InMemorySink', () => {
  it('records events in order', () => {
    const sink = new InMemorySink();
    sink.emit(anEvent('a'));
    sink.emit(anEvent('b'));
    expect(sink.snapshot().map((e) => e.detail)).toEqual(['a', 'b']);
  });

  it('returns a defensive copy from snapshot', () => {
    const sink = new InMemorySink();
    sink.emit(anEvent('a'));
    const snap = sink.snapshot() as unknown[];
    snap.push('mutation');
    expect(sink.snapshot()).toHaveLength(1);
  });
});

describe('SystemClock', () => {
  it('returns the current time in ms', () => {
    const before = Date.now();
    const now = new SystemClock().now();
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(Date.now());
  });
});
