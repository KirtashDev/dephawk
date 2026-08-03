import { openSync, writeSync } from 'node:fs';
import type { DhEvent } from '../../domain/event.js';
import type { Reporter } from '../../application/ports.js';

/** The append operation the reporter needs — injectable for testing. */
export type AppendFn = (data: string) => void;

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
 * The sink is opened **once, on construction** — which happens before the
 * interceptors are installed and therefore before any untrusted code runs — and
 * written through the resulting descriptor with `writeSync`. Two reasons:
 *
 * 1. It keeps dephawk's own writes off the patched `fs` surface, so the
 *    interceptors can refuse *everyone* access to the sink without dephawk
 *    having to exempt itself by name.
 * 2. The descriptor is `O_APPEND`, so concurrent writes from the several
 *    processes an install spawns land whole, one line per event.
 *
 * The write is synchronous so it completes before the process exits from its
 * `exit` hook. The reader parses defensively and skips any partial line.
 */
export class JsonlSinkReporter implements Reporter {
  private readonly append: AppendFn;

  constructor(path: string, append: AppendFn = openAppender(path)) {
    this.append = append;
  }

  report(events: readonly DhEvent[]): void {
    if (events.length === 0) {
      return;
    }
    const lines = events.map((event) => JSON.stringify(event)).join('\n');
    this.append(`${lines}\n`);
  }
}

/**
 * Open `path` for appending and return a writer over the descriptor.
 *
 * A failure here must not take the install down with it: guard is a monitor,
 * not a gate. We say so on stderr and carry on writing nothing, which surfaces
 * as an empty report rather than a crashed `npm ci`.
 */
function openAppender(path: string): AppendFn {
  let fd: number;
  try {
    fd = openSync(path, 'a');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`dephawk: cannot open the event sink (${message})\n`);
    return () => undefined;
  }

  // The descriptor is deliberately never closed. Events are flushed from an
  // `exit` handler, and `exit` listeners run in registration order — a close
  // registered here would fire first and turn every flush into EBADF. The
  // kernel closes it when the process goes, which is the only moment we would
  // have wanted to anyway.
  return (data) => {
    writeSync(fd, data);
  };
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
