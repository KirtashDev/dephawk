import { describe, it, expect } from 'vitest';
import { ConsoleReporter } from '../../../src/adapters/reporting/console-reporter.js';
import { mixed } from './events.js';

describe('ConsoleReporter', () => {
  it('writes the formatted report through the injected writer', () => {
    const chunks: string[] = [];
    const reporter = new ConsoleReporter({
      write: (text) => chunks.push(text),
      color: false,
    });
    reporter.report(mixed);
    const out = chunks.join('');
    expect(out).toContain('dephawk report');
    expect(out).toContain('evil-pkg');
    expect(out).not.toContain(String.fromCharCode(27)); // colour disabled -> no ANSI
  });
});
