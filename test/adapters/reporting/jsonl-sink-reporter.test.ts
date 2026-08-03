import { describe, it, expect } from 'vitest';
import {
  JsonlSinkReporter,
  parseSink,
} from '../../../src/adapters/reporting/jsonl-sink-reporter.js';
import { ev, mixed } from './events.js';

describe('JsonlSinkReporter', () => {
  it('appends one JSON line per event, newline-terminated', () => {
    const writes: string[] = [];
    const reporter = new JsonlSinkReporter('/tmp/sink.jsonl', (d) => {
      writes.push(d);
    });

    reporter.report(mixed);

    expect(writes).toHaveLength(1);
    const data = writes[0] ?? '';
    expect(data.endsWith('\n')).toBe(true);
    expect(data.trim().split('\n')).toHaveLength(mixed.length);
  });

  it('writes nothing for an empty batch', () => {
    const writes: string[] = [];
    new JsonlSinkReporter('/tmp/sink.jsonl', (d) => writes.push(d)).report([]);
    expect(writes).toHaveLength(0);
  });

  it('does not touch the filesystem when an append function is injected', () => {
    // The default appender opens the sink eagerly; an injected one must not,
    // or every unit test would litter the disk.
    expect(
      () => new JsonlSinkReporter('/definitely/not/a/directory/sink.jsonl', () => {}),
    ).not.toThrow();
  });

  it('round-trips through parseSink', () => {
    let buffer = '';
    const reporter = new JsonlSinkReporter('/tmp/sink.jsonl', (d) => {
      buffer += d;
    });

    // Two separate processes appending to the same sink.
    reporter.report([ev({ package: 'a', detail: '/x' })]);
    reporter.report([ev({ package: 'b', detail: '/y' })]);

    const events = parseSink(buffer);
    expect(events.map((e) => e.package)).toEqual(['a', 'b']);
    expect(events.map((e) => e.detail)).toEqual(['/x', '/y']);
  });

  it('parseSink skips blank and torn (unparseable) lines', () => {
    const good = JSON.stringify(ev({ package: 'ok', detail: '/z' }));
    const contents = `\n${good}\n{"package":"torn-half\n   \n`;
    const events = parseSink(contents);
    expect(events).toHaveLength(1);
    expect(events[0]?.package).toBe('ok');
  });
});
