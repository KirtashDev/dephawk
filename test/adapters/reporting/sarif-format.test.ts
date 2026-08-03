import { describe, it, expect } from 'vitest';
import { renderSarifReport } from '../../../src/adapters/reporting/sarif-format.js';
import { ev, mixed } from './events.js';

const meta = { toolVersion: '9.9.9', rootPath: '/proj' };

function render(events: Parameters<typeof renderSarifReport>[0]): {
  version: string;
  runs: {
    tool: { driver: { name: string; version: string; rules: { id: string }[] } };
    results: {
      ruleId: string;
      level: string;
      message: { text: string };
      locations: {
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number; startColumn?: number };
        };
      }[];
      partialFingerprints: Record<string, string>;
    }[];
  }[];
} {
  return JSON.parse(renderSarifReport(events, meta));
}

describe('renderSarifReport', () => {
  it('produces a 2.1.0 document naming the tool', () => {
    const sarif = render(mixed);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.tool.driver.name).toBe('dephawk');
    expect(sarif.runs[0]!.tool.driver.version).toBe('9.9.9');
  });

  it('reports only findings, not every mundane call', () => {
    // `mixed` is one violation, one sensitive-but-allowed, and two normal reads.
    const results = render(mixed).runs[0]!.results;
    expect(results).toHaveLength(2);
  });

  it('declares a rule for each capability it reports, and no others', () => {
    const run = render(mixed).runs[0]!;
    const ruleIds = run.tool.driver.rules.map((rule) => rule.id);

    expect(ruleIds).toEqual(['env.read', 'net.connect']);
    // Every result must point at a declared rule or GitHub rejects the file.
    for (const result of run.results) {
      expect(ruleIds).toContain(result.ruleId);
    }
  });

  it('maps a policy violation to error and a permitted-but-sensitive call to warning', () => {
    const results = render(mixed).runs[0]!.results;

    expect(results.find((r) => r.ruleId === 'net.connect')?.level).toBe('error');
    expect(results.find((r) => r.ruleId === 'env.read')?.level).toBe('warning');
  });

  it('names the package, the detail and the reason in the message', () => {
    const text = render(mixed).runs[0]!.results.find((r) => r.ruleId === 'net.connect')!
      .message.text;

    expect(text).toContain('evil-pkg');
    expect(text).toContain('collector.sketchy.example');
    expect(text).toContain('not allowlisted');
    expect(text).toContain('would be blocked in enforce mode');
  });

  it('points at the offending file, relative to the project root', () => {
    const events = [
      ev({
        allowed: false,
        reason: 'nope',
        stack: ['at steal (/proj/node_modules/evil-pkg/index.js:10:3)'],
      }),
    ];

    const location = render(events).runs[0]!.results[0]!.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('node_modules/evil-pkg/index.js');
    expect(location.region.startLine).toBe(10);
    expect(location.region.startColumn).toBe(3);
  });

  it('skips frames outside the project and takes the first one inside it', () => {
    const events = [
      ev({
        allowed: false,
        stack: [
          'at readFileSync (node:fs:100:5)',
          'at steal (/elsewhere/tool/index.js:1:1)',
          'at run (/proj/node_modules/evil-pkg/deep.js:4:2)',
        ],
      }),
    ];

    const location = render(events).runs[0]!.results[0]!.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('node_modules/evil-pkg/deep.js');
  });

  it('falls back to the manifest rather than dropping a locationless finding', () => {
    const events = [
      ev({ allowed: false, stack: ['at listOnTimeout (node:internal:1:1)'] }),
    ];

    const location = render(events).runs[0]!.results[0]!.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('package.json');
    expect(location.region.startLine).toBe(1);
  });

  it('collapses repeats into one result that says how many', () => {
    const repeated = [
      ev({ allowed: false }),
      ev({ allowed: false }),
      ev({ allowed: false }),
    ];
    const results = render(repeated).runs[0]!.results;

    expect(results).toHaveLength(1);
    expect(results[0]!.message.text).toContain('seen 3 times');
  });

  it('fingerprints a finding by who/what/where, so repeat runs do not reopen it', () => {
    const first = render([ev({ allowed: false })]).runs[0]!.results[0]!;
    const later = render([ev({ allowed: false }), ev({ allowed: false })]).runs[0]!
      .results[0]!;

    expect(first.partialFingerprints).toEqual(later.partialFingerprints);
    expect(Object.values(first.partialFingerprints)[0]).toContain('p');
  });

  it('renders an empty but valid document when nothing was found', () => {
    const sarif = render([]);

    expect(sarif.runs[0]!.results).toEqual([]);
    expect(sarif.runs[0]!.tool.driver.rules).toEqual([]);
  });

  it('labels an unattributed finding rather than blaming your code', () => {
    const events = [ev({ package: null, origin: 'unknown', allowed: false })];
    expect(render(events).runs[0]!.results[0]!.message.text).toContain('(unattributed)');
  });
});
