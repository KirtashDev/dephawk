import { describe, it, expect } from 'vitest';
import { JsonlSink } from '../../../src/adapters/sink/jsonl-sink.js';
import { parseSink } from '../../../src/adapters/reporting/jsonl-sink-reporter.js';
import type { DhEvent } from '../../../src/domain/event.js';

function event(detail: string): DhEvent {
  return {
    capability: 'fs.read',
    package: 'evil',
    origin: 'dependency',
    detail,
    stack: [],
    sensitive: true,
    allowed: false,
    blocked: true,
    timestamp: 0,
  };
}

describe('JsonlSink', () => {
  it('writes each event the instant it is emitted, not at the end', () => {
    // The whole point: a dependency that removes the process exit handler must
    // not be able to erase what already happened. There is no flush step here —
    // the record exists after `emit`, before anything gets a chance to tear down.
    const written: string[] = [];
    const sink = new JsonlSink('unused', (data) => written.push(data));

    sink.emit(event('/home/u/.ssh/id_rsa'));
    // Already durable, with no report()/flush() call.
    expect(written).toHaveLength(1);

    sink.emit(event('/home/u/.env'));
    expect(written).toHaveLength(2);

    const parsed = parseSink(written.join(''));
    expect(parsed.map((e) => e.detail)).toEqual(['/home/u/.ssh/id_rsa', '/home/u/.env']);
  });

  it('keeps the events in memory for a standalone report', () => {
    const sink = new JsonlSink('unused', () => undefined);
    sink.emit(event('/a'));
    sink.emit(event('/b'));
    expect(sink.snapshot().map((e) => e.detail)).toEqual(['/a', '/b']);
  });

  it('writes one whole line per event, so concurrent appends stay parseable', () => {
    const written: string[] = [];
    const sink = new JsonlSink('unused', (data) => written.push(data));
    sink.emit(event('/x'));
    expect(written[0]?.endsWith('\n')).toBe(true);
    expect(written[0]?.trimEnd().includes('\n')).toBe(false);
  });
});
