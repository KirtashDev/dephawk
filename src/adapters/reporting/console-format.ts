import { CAPABILITY_META } from '../../domain/capability.js';
import type { DhEvent } from '../../domain/event.js';
import type { Mode } from '../../domain/policy.js';
import { createStyler, type StyleName } from './ansi.js';
import { displayPackage, summarize, type Row, type Severity } from './report-model.js';

export { severityOf } from './report-model.js';
export type { Severity } from './report-model.js';

const ICON: Record<Severity, string> = {
  critical: '🚨',
  notice: '⚠️ ',
  normal: '✔️ ',
};

const COLOR: Record<Severity, StyleName> = {
  critical: 'red',
  notice: 'yellow',
  normal: 'green',
};

const MAX_DETAIL = 52;

export interface ConsoleFormatOptions {
  readonly color: boolean;
  /**
   * Active mode, when the caller knows it. Only used to decide whether
   * suggesting enforce mode makes sense.
   */
  readonly mode?: Mode;
}

/**
 * Render the terminal report as a string (pure — no I/O), so it can be tested
 * deterministically and reused by any writer.
 */
export function formatConsoleReport(
  events: readonly DhEvent[],
  options: ConsoleFormatOptions = { color: false },
): string {
  const style = createStyler(options.color);
  const title = style('bold', '🦅 dephawk report');

  if (events.length === 0) {
    return `${title} — no monitored activity recorded.\n`;
  }

  const { flagged, normalCount, blockedCount, culprits } = summarize(events);

  if (flagged.length === 0) {
    return `${title} — nothing sensitive touched. ${normalCount} calls seen.\n`;
  }

  const lines: string[] = [];
  lines.push(
    // `culprits` counts dependencies only, so it can be 0 while rows are
    // flagged: that is your own code, and saying "0 packages" would be a riddle.
    culprits === 0
      ? `${title} — nothing your dependencies did was sensitive; your own code touched something`
      : `${title} — ${style('bold', String(culprits))} package${culprits === 1 ? '' : 's'} touched something sensitive`,
  );
  lines.push('');

  const width = Math.min(
    28,
    Math.max(...flagged.map((row) => displayPackage(row).length)),
  );

  for (const row of flagged) {
    lines.push(formatRow(row, width, style));
  }

  lines.push('');
  lines.push(
    `  ${style('green', '✔️ ')} ${normalCount} other call${normalCount === 1 ? '' : 's'} looked normal`,
  );
  lines.push('');

  if (blockedCount > 0) {
    lines.push(
      `  ${style('red', String(blockedCount))} call${blockedCount === 1 ? '' : 's'} blocked by policy.`,
    );
  } else if (options.mode !== 'enforce') {
    // Advice, not a status line: in enforce mode nothing was blocked because
    // policy permitted everything above, and telling someone already enforcing
    // to enforce read like dephawk had lost track of what it was doing.
    lines.push(
      `  Run in enforce mode to block these →  ${style('bold', 'DEPHAWK_MODE=enforce')}`,
    );
  }
  lines.push('');

  return `${lines.join('\n')}\n`;
}

function formatRow(
  row: Row,
  width: number,
  style: ReturnType<typeof createStyler>,
): string {
  const name = displayPackage(row).padEnd(width);
  const label = CAPABILITY_META[row.capability].label.padEnd(7);
  const detail = truncate(row.detail, MAX_DETAIL);
  const suffix = row.count > 1 ? style('dim', ` (x${row.count})`) : '';
  const blocked = row.blocked ? ` ${style('red', '[blocked]')}` : '';
  return `  ${ICON[row.severity]}  ${style(COLOR[row.severity], name)}  →  ${style('cyan', label)} ${detail}${suffix}${blocked}`;
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
