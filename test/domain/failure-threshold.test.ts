import { describe, it, expect } from 'vitest';
import {
  describeFailure,
  failsThreshold,
  isFailureThreshold,
  FAILURE_THRESHOLDS,
} from '../../src/domain/failure-threshold.js';
import { createEvent, type DhEvent } from '../../src/domain/event.js';

function ev(partial: Partial<Parameters<typeof createEvent>[0]> = {}): DhEvent {
  return createEvent({
    capability: 'fs.read',
    package: 'evil-pkg',
    origin: 'dependency',
    detail: '/app/x.js',
    stack: [],
    sensitive: false,
    allowed: true,
    blocked: false,
    timestamp: 0,
    ...partial,
  });
}

const mundane = ev();
const sensitiveButAllowed = ev({ sensitive: true, detail: '/home/a/.npmrc' });
const denied = ev({ allowed: false, reason: 'nope' });
const deniedAndBlocked = ev({ allowed: false, blocked: true, reason: 'nope' });

describe('isFailureThreshold', () => {
  it('accepts every documented level and nothing else', () => {
    for (const level of FAILURE_THRESHOLDS) {
      expect(isFailureThreshold(level)).toBe(true);
    }
    expect(isFailureThreshold('critical')).toBe(false);
    expect(isFailureThreshold('')).toBe(false);
  });
});

describe('failsThreshold', () => {
  it('never fails at none, whatever happened', () => {
    expect(failsThreshold([deniedAndBlocked], 'none')).toBe(false);
  });

  it('fails at blocked only when a call was actually prevented', () => {
    expect(failsThreshold([deniedAndBlocked], 'blocked')).toBe(true);
    // Observe mode records the denial but does not block, so this must pass.
    expect(failsThreshold([denied], 'blocked')).toBe(false);
  });

  it('fails at violation on a denial, blocked or not', () => {
    expect(failsThreshold([denied], 'violation')).toBe(true);
    expect(failsThreshold([deniedAndBlocked], 'violation')).toBe(true);
    expect(failsThreshold([sensitiveButAllowed], 'violation')).toBe(false);
  });

  it('fails at sensitive on an allowed-but-sensitive call', () => {
    expect(failsThreshold([sensitiveButAllowed], 'sensitive')).toBe(true);
    expect(failsThreshold([mundane], 'sensitive')).toBe(false);
  });

  it('covers denials that are not sensitive at the sensitive level', () => {
    // An unlisted outbound connection is a violation with nothing secret about
    // it; the loosest threshold must not miss what a stricter one catches.
    const connect = ev({ capability: 'net.connect', allowed: false, sensitive: false });
    expect(failsThreshold([connect], 'sensitive')).toBe(true);
  });

  it('passes a clean run at every level', () => {
    for (const level of FAILURE_THRESHOLDS) {
      expect(failsThreshold([mundane], level)).toBe(false);
      expect(failsThreshold([], level)).toBe(false);
    }
  });
});

describe('describeFailure', () => {
  it('counts only what the threshold cares about', () => {
    const events = [mundane, sensitiveButAllowed, denied, deniedAndBlocked];
    expect(describeFailure(events, 'blocked')).toBe('1 blocked call');
    expect(describeFailure(events, 'violation')).toBe('2 policy violations');
    expect(describeFailure(events, 'sensitive')).toBe('3 sensitive calls');
  });
});
