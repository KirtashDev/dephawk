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
    this.write = options.write ?? ((text) => process.stderr.write(text));
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
