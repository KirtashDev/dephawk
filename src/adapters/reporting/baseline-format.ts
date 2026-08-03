import { CAPABILITY_META } from '../../domain/capability.js';
import type { Behaviour, BaselineDiff } from '../../domain/behaviour-baseline.js';
import { createStyler } from './ansi.js';

/**
 * Render a baseline diff for the terminal.
 *
 * Additions are the point and get the space; removals are reported quietly
 * because they usually mean a code path did not run this time, not that
 * anything improved. Pure, like the other formatters, so the wording is
 * testable without running a process.
 */
export function formatBaselineDiff(
  diff: BaselineDiff,
  options: { readonly color: boolean } = { color: false },
): string {
  const style = createStyler(options.color);
  const title = style('bold', '🦅 dephawk baseline');

  if (diff.added.length === 0 && diff.removed.length === 0) {
    return `${title} — no change: every dependency did what it did last time.\n`;
  }

  const lines: string[] = [];

  if (diff.added.length === 0) {
    lines.push(`${title} — nothing new.`);
  } else {
    lines.push(
      `${title} — ${style('bold', String(diff.added.length))} new behaviour${
        diff.added.length === 1 ? '' : 's'
      } since the baseline was recorded`,
    );
    lines.push('');
    for (const behaviour of diff.added) {
      lines.push(`  ${style('yellow', '+')} ${describe(behaviour, style)}`);
    }
  }

  if (diff.removed.length > 0) {
    lines.push('');
    lines.push(
      style(
        'dim',
        `  ${String(diff.removed.length)} recorded behaviour${
          diff.removed.length === 1 ? '' : 's'
        } did not happen this run (usually a code path that was not exercised)`,
      ),
    );
  }

  lines.push('');
  lines.push(
    style('dim', '  Re-record when the change is expected:  dephawk run --record …'),
  );
  lines.push('');

  return `${lines.join('\n')}\n`;
}

function describe(behaviour: Behaviour, style: ReturnType<typeof createStyler>): string {
  const who =
    behaviour.package ??
    (behaviour.origin === 'application' ? '(your code)' : '(unattributed)');
  const label = CAPABILITY_META[behaviour.capability].label;
  return `${style('bold', who)}  →  ${style('cyan', label)} ${behaviour.detail}`;
}
