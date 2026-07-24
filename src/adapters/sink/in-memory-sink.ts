import type { DhEvent } from '../../domain/event.js';
import type { EventSink } from '../../application/ports.js';

/** The default {@link EventSink}: keeps every event in insertion order in memory. */
export class InMemorySink implements EventSink {
  private readonly events: DhEvent[] = [];

  emit(event: DhEvent): void {
    this.events.push(event);
  }

  snapshot(): readonly DhEvent[] {
    return [...this.events];
  }
}
