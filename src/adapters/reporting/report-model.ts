import type { DhEvent } from '../../domain/event.js';

export type Severity = 'critical' | 'notice' | 'normal';

/** Classify an event by how much attention it deserves. */
export function severityOf(event: DhEvent): Severity {
  if (!event.allowed) {
    return 'critical'; // a policy violation: blocked, or would be in enforce mode
  }
  if (event.sensitive) {
    return 'notice'; // touched something sensitive, but permitted
  }
  return 'normal';
}

/** A group of identical events, collapsed with a count. */
export interface Row {
  readonly severity: Severity;
  readonly package: string | null;
  readonly capability: DhEvent['capability'];
  readonly detail: string;
  readonly blocked: boolean;
  count: number;
}

const ORDER: Record<Severity, number> = { critical: 0, notice: 1, normal: 2 };

/** Collapse identical events into counted rows, most-severe first. */
export function aggregate(events: readonly DhEvent[]): Row[] {
  const byKey = new Map<string, Row>();
  for (const event of events) {
    const severity = severityOf(event);
    const key = `${severity}|${event.package ?? ''}|${event.capability}|${event.detail}|${event.blocked}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      byKey.set(key, {
        severity,
        package: event.package,
        capability: event.capability,
        detail: event.detail,
        blocked: event.blocked,
        count: 1,
      });
    }
  }
  return [...byKey.values()].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

/** Common summary counts derived from aggregated rows. */
export interface ReportSummary {
  readonly rows: readonly Row[];
  readonly flagged: readonly Row[];
  readonly criticalCount: number;
  readonly noticeCount: number;
  readonly normalCount: number;
  readonly blockedCount: number;
  readonly culprits: number;
}

export function summarize(events: readonly DhEvent[]): ReportSummary {
  const rows = aggregate(events);
  const flagged = rows.filter((r) => r.severity !== 'normal');
  const sumWhere = (predicate: (r: Row) => boolean): number =>
    rows.filter(predicate).reduce((n, r) => n + r.count, 0);

  return {
    rows,
    flagged,
    criticalCount: sumWhere((r) => r.severity === 'critical'),
    noticeCount: sumWhere((r) => r.severity === 'notice'),
    normalCount: sumWhere((r) => r.severity === 'normal'),
    blockedCount: sumWhere((r) => r.blocked),
    culprits: new Set(flagged.map((r) => r.package ?? '(your code)')).size,
  };
}
