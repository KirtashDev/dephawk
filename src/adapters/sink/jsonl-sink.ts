import type { DhEvent } from '../../domain/event.js';
import type { EventSink } from '../../application/ports.js';
import { openAppender, type AppendFn } from '../reporting/jsonl-sink-reporter.js';

/**
 * An {@link EventSink} that writes each event to the shared JSONL file **the
 * moment it is decided**, not in one batch at exit.
 *
 * This is what makes the aggregated `run`/`guard` report tamper-resistant.
 * The obvious way to blind dephawk is to stop it reporting, and the report used
 * to be produced from a `process.on('exit')` handler — a listener any
 * dependency can drop with `process.removeAllListeners('exit')`, after which
 * the buffered events were never written and the CLI's `--fail-on` gate passed
 * on an empty file. Reproduced: a dependency read a secret and then removed the
 * exit listeners, and the run exited 0 with "no monitored activity recorded".
 *
 * Streaming closes that off. Every event is already on disk by the time the
 * call that produced it returns, so removing the exit handler loses nothing the
 * parent has not already seen. The events are held in memory as well, so a
 * standalone run can still print its own end-of-run report.
 *
 * The descriptor is opened on construction — before the interceptors are
 * installed, so writes go through the raw fd rather than the patched `fs`
 * surface, and `O_APPEND` keeps each line whole across the several processes an
 * install spawns. See {@link import('../reporting/jsonl-sink-reporter.js')}.
 */
export class JsonlSink implements EventSink {
  private readonly events: DhEvent[] = [];
  private readonly append: AppendFn;

  constructor(path: string, append: AppendFn = openAppender(path)) {
    this.append = append;
  }

  emit(event: DhEvent): void {
    this.events.push(event);
    this.append(`${JSON.stringify(event)}\n`);
  }

  snapshot(): readonly DhEvent[] {
    return [...this.events];
  }
}
