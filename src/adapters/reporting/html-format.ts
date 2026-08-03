import { CAPABILITY_META } from '../../domain/capability.js';
import type { DhEvent } from '../../domain/event.js';
import { displayPackage, summarize, type Row } from './report-model.js';

export interface HtmlReportMeta {
  /** ISO timestamp string for "generated at". */
  readonly generatedAt: string;
}

const SEVERITY_LABEL: Record<Row['severity'], string> = {
  critical: 'violation',
  notice: 'sensitive',
  normal: 'normal',
};

/**
 * Render a fully self-contained, shareable HTML report. No external assets,
 * all CSS inlined — safe to open from disk or drop into a GitHub comment as an
 * artifact. Pure function of its inputs for deterministic testing.
 */
export function renderHtmlReport(
  events: readonly DhEvent[],
  meta: HtmlReportMeta,
): string {
  const { flagged, criticalCount, noticeCount, normalCount, blockedCount, culprits } =
    summarize(events);

  const cards = flagged.map(renderRow).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>dephawk report</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2.5rem 1rem; background: #0b0e14; color: #e6e6e6;
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  .wrap { max-width: 860px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin: 0 0 .25rem; }
  .sub { color: #8b93a7; margin: 0 0 1.75rem; }
  .stats { display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.75rem; }
  .stat { background: #141925; border: 1px solid #232a3a; border-radius: 12px; padding: .8rem 1.1rem; flex: 1 1 140px; }
  .stat b { display: block; font-size: 1.6rem; }
  .stat.crit b { color: #ff6b6b; } .stat.note b { color: #ffd166; } .stat.ok b { color: #4ade80; }
  .stat span { color: #8b93a7; font-size: .85rem; }
  .row {
    display: grid; grid-template-columns: auto 1fr auto; gap: .5rem 1rem; align-items: center;
    background: #141925; border: 1px solid #232a3a; border-left-width: 4px; border-radius: 10px;
    padding: .8rem 1rem; margin-bottom: .6rem; overflow: hidden;
  }
  .row.critical { border-left-color: #ff6b6b; } .row.notice { border-left-color: #ffd166; }
  .icon { font-size: 1.3rem; }
  .pkg { font-weight: 600; }
  .cap { color: #6ee7ff; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
  .detail { color: #b8c0d0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; word-break: break-all; }
  .tag { font-size: .72rem; padding: .12rem .5rem; border-radius: 999px; white-space: nowrap; }
  .tag.blocked { background: #3a1414; color: #ff9d9d; border: 1px solid #5a1f1f; }
  .tag.count { background: #1c2330; color: #8b93a7; }
  .empty { text-align: center; padding: 3rem 1rem; color: #8b93a7; }
  footer { margin-top: 2rem; padding-top: 1.25rem; border-top: 1px solid #232a3a; color: #8b93a7; font-size: .82rem; }
  footer b { color: #cbd2e0; }
  code { background: #1c2330; padding: .08rem .35rem; border-radius: 5px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>🦅 dephawk report</h1>
  <p class="sub">${culprits === 0 ? 'Nothing sensitive was touched.' : `${culprits} package${culprits === 1 ? '' : 's'} touched something sensitive.`} Generated ${esc(meta.generatedAt)}.</p>

  <div class="stats">
    <div class="stat crit"><b>${criticalCount}</b><span>violations</span></div>
    <div class="stat note"><b>${noticeCount}</b><span>sensitive but allowed</span></div>
    <div class="stat"><b>${blockedCount}</b><span>blocked</span></div>
    <div class="stat ok"><b>${normalCount}</b><span>normal calls</span></div>
  </div>

  ${flagged.length === 0 ? '<div class="empty">No packages tried anything sensitive. 🎉</div>' : cards}

  <footer>
    <p><b>Honest threat model.</b> dephawk is a high-signal tripwire and policy layer, not an unbreakable sandbox. Attribution uses stack traces (obscurable by a determined attacker); native addons and code that bypasses the standard built-ins are not covered; <code>process.env</code> interception is best-effort. For a hard boundary, combine with OS-level isolation.</p>
  </footer>
</div>
</body>
</html>
`;
}

function renderRow(row: Row): string {
  const icon = row.severity === 'critical' ? '🚨' : '⚠️';
  const pkg = esc(displayPackage(row));
  const label = esc(CAPABILITY_META[row.capability].label);
  const detail = esc(row.detail);
  const tags = [
    row.blocked ? '<span class="tag blocked">blocked</span>' : '',
    row.count > 1 ? `<span class="tag count">×${row.count}</span>` : '',
    `<span class="tag count">${SEVERITY_LABEL[row.severity]}</span>`,
  ]
    .filter(Boolean)
    .join(' ');
  return `  <div class="row ${row.severity}">
    <div class="icon">${icon}</div>
    <div><span class="pkg">${pkg}</span> &nbsp; <span class="cap">${label}</span> <span class="detail">${detail}</span></div>
    <div>${tags}</div>
  </div>`;
}

function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
