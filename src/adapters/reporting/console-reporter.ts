import type { DhEvent } from '../../domain/event.js';
import type { Mode } from '../../domain/policy.js';
import type { Reporter } from '../../application/ports.js';
import { shouldColor } from './ansi.js';
import { formatConsoleReport } from './console-format.js';

export interface ConsoleReporterOptions {
  /** Where to write. Defaults to stderr so it never pollutes program stdout. */
  readonly write?: (text: string) => void;
  /** Force colour on/off. Defaults to auto-detection (NO_COLOR/TTY). */
  readonly color?: boolean;
  /** Active mode, so the report does not advise enforcing when it already is. */
  readonly mode?: Mode;
}

/**
 * Prints the human-readable summary. Writes to stderr by default so a monitored
 * program's own stdout stays clean and pipeable.
 */
export class ConsoleReporter implements Reporter {
  private readonly write: (text: string) => void;
  private readonly color: boolean;
  private readonly mode: Mode | undefined;

  constructor(options: ConsoleReporterOptions = {}) {
    // Capture `stderr.write` once, bound, at construction. The reporter is built
    // in dephawk/register before any dependency runs, so this is the pristine
    // function — a dependency that later swaps `process.stderr.write` (to swallow
    // the console report, which in observe mode is the *only* signal) cannot reach
    // it. Resolving `process.stderr.write` lazily on each report left that hole.
    const stderrWrite = process.stderr.write.bind(process.stderr);
    this.write = options.write ?? ((text) => stderrWrite(text));
    this.color = options.color ?? shouldColor(process.env, Boolean(process.stderr.isTTY));
    this.mode = options.mode;
  }

  report(events: readonly DhEvent[]): void {
    const formatted = formatConsoleReport(events, {
      color: this.color,
      ...(this.mode === undefined ? {} : { mode: this.mode }),
    });
    this.write(`\n${formatted}`);
  }
}
