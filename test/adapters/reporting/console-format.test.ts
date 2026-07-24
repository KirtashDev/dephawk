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
    const dup = ev({ package: 'spammy', capability: 'net.connect', detail: 'h', allowed: false });
    const out = formatConsoleReport([dup, dup, dup], { color: false });
    expect(out).toContain('(x3)');
  });

  it('emits ANSI codes only when colour is enabled', () => {
    expect(formatConsoleReport(mixed, { color: true })).toContain(ESC);
    expect(formatConsoleReport(mixed, { color: false })).not.toContain(ESC);
  });
});
