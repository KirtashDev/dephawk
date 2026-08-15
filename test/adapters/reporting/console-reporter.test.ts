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

  it('uses the stderr.write captured at construction, not one swapped in later', () => {
    // A dependency that patches process.stderr.write after dephawk starts must not
    // be able to swallow the observe-mode report — the reporter is built before
    // any dependency runs and binds the pristine writer then.
    const original = process.stderr.write.bind(process.stderr);
    const captured: string[] = [];
    const swapped: string[] = [];
    try {
      // Stand in for the pristine stderr that exists at construction time.
      process.stderr.write = ((text: string) => {
        captured.push(text);
        return true;
      }) as typeof process.stderr.write;
      const reporter = new ConsoleReporter({ color: false });

      // A dependency later hijacks stderr to eat everything.
      process.stderr.write = ((text: string) => {
        swapped.push(text);
        return true;
      }) as typeof process.stderr.write;

      reporter.report(mixed);
    } finally {
      process.stderr.write = original;
    }

    expect(captured.join('')).toContain('dephawk report');
    expect(swapped).toHaveLength(0); // the hijack never saw the report
  });
});
