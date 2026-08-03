import { describe, it, expect } from 'vitest';
import {
  formatConsoleReport,
  severityOf,
} from '../../../src/adapters/reporting/console-format.js';
import { ev, mixed } from './events.js';

const ESC = '';

describe('severityOf', () => {
  it('ranks violations, sensitive-allowed, and normal', () => {
    expect(severityOf(ev({ allowed: false }))).toBe('critical');
    expect(severityOf(ev({ allowed: true, sensitive: true }))).toBe('notice');
    expect(severityOf(ev({ allowed: true, sensitive: false }))).toBe('normal');
  });
});

describe('formatConsoleReport', () => {
  it('reports no activity for an empty run', () => {
    expect(formatConsoleReport([], { color: false })).toContain('no monitored activity');
  });

  it('reports nothing-sensitive when only normal calls happened', () => {
    const out = formatConsoleReport([ev(), ev()], { color: false });
    expect(out).toContain('nothing sensitive touched');
    expect(out).toContain('2 calls seen');
  });

  it('summarises a mixed run', () => {
    const out = formatConsoleReport(mixed, { color: false });
    expect(out).toContain('2 packages touched something sensitive');
    expect(out).toContain('evil-pkg');
    expect(out).toContain('collector.sketchy.example');
    expect(out).toContain('@sentry/node');
    expect(out).toContain('2 other calls looked normal');
    expect(out).toContain('DEPHAWK_MODE=enforce');
  });

  it('shows blocked markers and count in enforce mode', () => {
    const out = formatConsoleReport(
      [ev({ package: 'x', allowed: false, blocked: true, detail: 'h' })],
      { color: false },
    );
    expect(out).toContain('[blocked]');
    expect(out).toContain('1 call blocked by policy');
    expect(out).not.toContain('DEPHAWK_MODE=enforce');
  });

  it('aggregates identical events with a count', () => {
    const dup = ev({
      package: 'spammy',
      capability: 'net.connect',
      detail: 'h',
      allowed: false,
    });
    const out = formatConsoleReport([dup, dup, dup], { color: false });
    expect(out).toContain('(x3)');
  });

  it('emits ANSI codes only when colour is enabled', () => {
    expect(formatConsoleReport(mixed, { color: true })).toContain(ESC);
    expect(formatConsoleReport(mixed, { color: false })).not.toContain(ESC);
  });
});

describe('formatConsoleReport — the advice has to make sense', () => {
  it('does not tell someone already enforcing to enforce', () => {
    // Nothing was blocked because policy permitted everything; suggesting
    // enforce mode to a run that is already in it read like a bug, and was one.
    const out = formatConsoleReport([ev({ package: 'x', sensitive: true })], {
      color: false,
      mode: 'enforce',
    });

    expect(out).toContain('touched something sensitive');
    expect(out).not.toContain('DEPHAWK_MODE=enforce');
  });

  it('still suggests it in observe mode', () => {
    const out = formatConsoleReport([ev({ package: 'x', sensitive: true })], {
      color: false,
      mode: 'observe',
    });

    expect(out).toContain('DEPHAWK_MODE=enforce');
  });

  it('does not count your own code as a culprit package', () => {
    // dephawk watches dependencies. Reading your own .env is not a finding
    // against you, and "1 package touched something sensitive" pointing at
    // `(your code)` was the loudest wrong number in the report.
    const out = formatConsoleReport(
      [
        ev({
          package: null,
          origin: 'application',
          detail: '/app/.env',
          sensitive: true,
        }),
      ],
      { color: false },
    );

    expect(out).not.toContain('1 package touched');
    expect(out).toContain('your own code touched something');
    // And it is still listed — silence would be worse than a wrong count.
    expect(out).toContain('(your code)');
    expect(out).toContain('/app/.env');
  });

  it('counts unattributed calls as culprits, because they are not yours', () => {
    const out = formatConsoleReport(
      [ev({ package: null, origin: 'unknown', detail: '/app/.env', sensitive: true })],
      { color: false },
    );

    expect(out).toContain('1 package touched something sensitive');
    expect(out).toContain('(unattributed)');
  });
});
