import { appendFileSync } from 'node:fs';
import type { DhEvent } from '../../domain/event.js';
import type { Reporter } from '../../application/ports.js';

/** The append operation the reporter needs — injectable for testing. */
export type AppendFn = (path: string, data: string) => void;

const defaultAppend: AppendFn = (path, data) => {
  appendFileSync(path, data);
};

/**
 * Writes each collected event as one line of JSON (JSONL) to a shared file.
 *
 * This is the aggregation channel for {@link import('../../cli.js')}'s `guard`
 * command: every monitored process spawned during an install (the package
 * manager itself and every dependency lifecycle script) appends its events to
 * the same file, and the parent reads them back to print a single, unified
 * report — instead of each short-lived process clobbering its own console/HTML
 * output.
 *
 * The write is synchronous (`appendFileSync`, `O_APPEND`) so it completes before
 * the process exits from its `beforeExit` hook, and one line per event keeps
 * concurrent appends from interleaving in the common case. The reader parses
 * defensively and skips any partial line.
 */
export class JsonlSinkReporter implements Reporter {
  private readonly path: string;
  private readonly append: AppendFn;

  constructor(path: string, append: AppendFn = defaultAppend) {
    this.path = path;
    this.append = append;
  }

  report(events: readonly DhEvent[]): void {
    if (events.length === 0) {
      return;
    }
    const lines = events.map((event) => JSON.stringify(event)).join('\n');
    this.append(this.path, `${lines}\n`);
  }
}

/** Parse a JSONL sink file's contents into events, skipping any malformed line. */
export function parseSink(contents: string): DhEvent[] {
  const events: DhEvent[] = [];
  for (const line of contents.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      continue;
    }
    try {
      events.push(JSON.parse(trimmed) as DhEvent);
    } catch {
      // A torn line from a large concurrent append — drop it rather than crash.
    }
  }
  return events;
}
