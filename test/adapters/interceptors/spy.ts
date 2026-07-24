import type { Decision, InterceptedCall } from '../../../src/application/ports.js';

/** A record spy that captures calls and lets a test choose the decision. */
export function recordSpy() {
  const calls: InterceptedCall[] = [];
  let decision: Decision = { allow: true };
  return {
    calls,
    record(call: InterceptedCall): Decision {
      calls.push(call);
      return decision;
    },
    allow(): void {
      decision = { allow: true };
    },
    deny(reason = 'blocked'): void {
      decision = { allow: false, reason };
    },
    get last(): InterceptedCall | undefined {
      return calls[calls.length - 1];
    },
  };
}
