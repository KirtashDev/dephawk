import type { CapabilityRequest } from '../../src/domain/capability-request.js';
import type { DhEvent } from '../../src/domain/event.js';
import type { Verdict } from '../../src/domain/verdict.js';
import type {
  Attribution,
  Attributor,
  CapabilityInterceptor,
  Clock,
  Decision,
  Disposable,
  EventSink,
  InterceptedCall,
  PolicyEngine,
  Reporter,
} from '../../src/application/ports.js';

export class FakeSink implements EventSink {
  readonly events: DhEvent[] = [];
  emit(event: DhEvent): void {
    this.events.push(event);
  }
  snapshot(): readonly DhEvent[] {
    return [...this.events];
  }
}

export class FakeClock implements Clock {
  private value: number;
  constructor(start = 1000) {
    this.value = start;
  }
  /** Each call advances by 1ms so ordering is observable. */
  now(): number {
    return this.value++;
  }
}

export class FakeAttributor implements Attributor {
  constructor(private readonly result: Attribution) {}
  attribute(_rawStack: string): Attribution {
    return this.result;
  }
}

export class StubPolicyEngine implements PolicyEngine {
  readonly seen: CapabilityRequest[] = [];
  constructor(private readonly verdict: Verdict | ((r: CapabilityRequest) => Verdict)) {}
  evaluate(req: CapabilityRequest): Verdict {
    this.seen.push(req);
    return typeof this.verdict === 'function' ? this.verdict(req) : this.verdict;
  }
}

export class FakeInterceptor implements CapabilityInterceptor {
  record: ((call: InterceptedCall) => Decision) | undefined;
  installed = 0;
  disposed = 0;
  constructor(readonly name: string) {}
  install(record: (call: InterceptedCall) => Decision): Disposable {
    this.installed++;
    this.record = record;
    return {
      dispose: () => {
        this.disposed++;
      },
    };
  }
}

export class FakeReporter implements Reporter {
  readonly calls: (readonly DhEvent[])[] = [];
  constructor(private readonly async = false) {}
  report(events: readonly DhEvent[]): void | Promise<void> {
    this.calls.push(events);
    if (this.async) {
      return Promise.resolve();
    }
  }
}
