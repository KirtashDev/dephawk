import { describe, it, expect } from 'vitest';
import {
  isDephawkConfigPath,
  protectedPathAffectedBy,
} from '../../src/domain/protected-path.js';

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

describe('isDephawkConfigPath — planting dephawk config for the next run', () => {
  it.each([
    '/repo/dephawk.config.js',
    '/repo/dephawk.config.mjs',
    '/repo/dephawk.config.cjs',
    'dephawk.config.js',
    'C:\\proj\\dephawk.config.js',
    '/repo/DEPHAWK.CONFIG.JS', // case-insensitive (matches on macOS/Windows)
  ])('flags %s', (path) => {
    expect(isDephawkConfigPath(path)).toBe(true);
  });

  it.each([
    '/repo/dephawk.config.ts', // not an auto-discovered name
    '/repo/dephawk.config.json',
    '/repo/my-dephawk.config.js.bak',
    '/repo/src/config.js',
    '/repo/dephawk.config.js/notes.txt', // a dir named like the config, then a file
  ])('does not flag %s', (path) => {
    expect(isDephawkConfigPath(path)).toBe(false);
  });
});

// Node's July 2026 release fixed its Permission Model over-granting filesystem
// access (CVE-2026-58043, HIGH) because its radix tree matched a granted
// `/home/app/data` against a never-allowlisted sibling `/home/app/data-secrets`:
// one string really is a prefix of the other. dephawk does the same *shape* of
// matching in several places, so each is pinned here in both directions —
// over-granting (treating a sibling as covered) and under-detecting (letting a
// genuinely contained path through).
describe('protectedPathAffectedBy — prefix boundaries (the CVE-2026-58043 class)', () => {
  const protectedPaths = ['/tmp/dephawk-sink/events.jsonl'];

  it('does not treat a name-prefix sibling as the protected path', () => {
    expect(
      protectedPathAffectedBy('/tmp/dephawk-sink/events.jsonl.bak', protectedPaths),
    ).toBeNull();
    expect(
      protectedPathAffectedBy('/tmp/dephawk-sink-evil/events.jsonl', protectedPaths),
    ).toBeNull();
    expect(protectedPathAffectedBy('/tmp/dephawk-sinkhole', protectedPaths)).toBeNull();
  });

  it('still catches the file itself and any ancestor directory', () => {
    expect(
      protectedPathAffectedBy('/tmp/dephawk-sink/events.jsonl', protectedPaths),
    ).toBe(protectedPaths[0]);
    expect(protectedPathAffectedBy('/tmp/dephawk-sink', protectedPaths)).toBe(
      protectedPaths[0],
    );
    expect(protectedPathAffectedBy('/tmp', protectedPaths)).toBe(protectedPaths[0]);
  });

  it('catches a path contained by a protected directory', () => {
    // Today every protected path is a file, so this is the containment guarantee
    // for the next one that is not.
    expect(protectedPathAffectedBy('/var/dephawk/log.jsonl', ['/var/dephawk'])).toBe(
      '/var/dephawk',
    );
    expect(
      protectedPathAffectedBy('/var/dephawk-other/log', ['/var/dephawk']),
    ).toBeNull();
  });
});
