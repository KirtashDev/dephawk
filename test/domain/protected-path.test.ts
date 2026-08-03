import { describe, it, expect } from 'vitest';
import { protectedPathAffectedBy } from '../../src/domain/protected-path.js';

const sink = '/tmp/dephawk-guard-a1b2/events.jsonl';
const guarded = [sink];

describe('protectedPathAffectedBy', () => {
  it('matches the protected file itself', () => {
    expect(protectedPathAffectedBy(sink, guarded)).toBe(sink);
  });

  it('matches an enclosing directory, so removing it counts as tampering', () => {
    expect(protectedPathAffectedBy('/tmp/dephawk-guard-a1b2', guarded)).toBe(sink);
    expect(protectedPathAffectedBy('/tmp', guarded)).toBe(sink);
  });

  it('does not match a sibling with the protected path as a prefix', () => {
    expect(protectedPathAffectedBy('/tmp/dephawk-guard-a1b2/other', guarded)).toBeNull();
    expect(protectedPathAffectedBy(`${sink}.bak`, guarded)).toBeNull();
  });

  it('does not match unrelated paths, or match anything with no protected paths', () => {
    expect(protectedPathAffectedBy('/home/alice/.npmrc', guarded)).toBeNull();
    expect(protectedPathAffectedBy(sink, [])).toBeNull();
  });

  it('reports which of several protected paths was hit', () => {
    const other = '/tmp/dephawk-guard-zzz/events.jsonl';
    expect(protectedPathAffectedBy(other, [sink, other])).toBe(other);
  });
});
