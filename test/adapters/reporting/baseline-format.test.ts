import { describe, it, expect } from 'vitest';
import { formatBaselineDiff } from '../../../src/adapters/reporting/baseline-format.js';
import type { Behaviour } from '../../../src/domain/behaviour-baseline.js';

const added: Behaviour = {
  package: 'httpclient',
  origin: 'dependency',
  capability: 'net.resolve',
  detail: 'telemetry.vendor.example',
};

const removed: Behaviour = {
  package: 'old-pkg',
  origin: 'dependency',
  capability: 'fs.read',
  detail: './.npmrc',
};

describe('formatBaselineDiff', () => {
  it('says plainly when nothing changed', () => {
    const out = formatBaselineDiff({ added: [], removed: [] });
    expect(out).toContain('no change');
  });

  it('leads with what is new, naming the package and what it did', () => {
    const out = formatBaselineDiff({ added: [added], removed: [] });

    expect(out).toContain('1 new behaviour');
    expect(out).toContain('httpclient');
    expect(out).toContain('telemetry.vendor.example');
    expect(out).toContain('dns');
  });

  it('pluralises', () => {
    const out = formatBaselineDiff({
      added: [added, { ...added, detail: 'other.example' }],
      removed: [],
    });
    expect(out).toContain('2 new behaviours');
  });

  it('mentions removals quietly, without calling them a problem', () => {
    const out = formatBaselineDiff({ added: [], removed: [removed] });

    expect(out).toContain('nothing new');
    expect(out).toContain('did not happen this run');
    expect(out).not.toContain('new behaviour ');
  });

  it('tells you how to accept the change', () => {
    const out = formatBaselineDiff({ added: [added], removed: [] });
    expect(out).toContain('--record');
  });

  it('labels a nameless behaviour by origin rather than blaming your code', () => {
    const out = formatBaselineDiff({
      added: [{ ...added, package: null, origin: 'unknown' }],
      removed: [],
    });
    expect(out).toContain('(unattributed)');
  });

  it('emits no escape codes when colour is off', () => {
    const out = formatBaselineDiff({ added: [added], removed: [removed] });
    // eslint-disable-next-line no-control-regex
    expect(/\[/.test(out)).toBe(false);
  });
});
