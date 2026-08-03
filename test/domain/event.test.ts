import { describe, it, expect } from 'vitest';
import { createEvent } from '../../src/domain/event.js';

const base = {
  capability: 'fs.read' as const,
  package: 'left-pad' as string | null,
  origin: 'dependency' as const,
  detail: '/home/alice/.ssh/id_rsa',
  stack: ['at left-pad'],
  sensitive: true,
  allowed: false,
  blocked: false,
  timestamp: 42,
};

describe('createEvent', () => {
  it('produces a frozen event', () => {
    const event = createEvent(base);
    expect(Object.isFrozen(event)).toBe(true);
    expect(Object.isFrozen(event.stack)).toBe(true);
  });

  it('copies the stack so later mutation of the input does not leak in', () => {
    const stack = ['a'];
    const event = createEvent({ ...base, stack });
    stack.push('b');
    expect(event.stack).toEqual(['a']);
  });

  it('omits reason when not provided', () => {
    const event = createEvent(base);
    expect('reason' in event).toBe(false);
  });

  it('includes reason when provided', () => {
    const event = createEvent({ ...base, reason: 'blocked' });
    expect(event.reason).toBe('blocked');
  });

  it('treats an explicit undefined reason as absent', () => {
    const event = createEvent({ ...base, reason: undefined });
    expect('reason' in event).toBe(false);
  });
});
