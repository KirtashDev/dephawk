import { describe, it, expect } from 'vitest';
import { pathMatches, pathMatchesAny } from '../../src/domain/path-glob.js';

describe('pathMatches', () => {
  it('matches an exact path', () => {
    expect(pathMatches('/a/b/c.txt', '/a/b/c.txt')).toBe(true);
  });

  it('matches a directory prefix', () => {
    expect(pathMatches('/a/b/c.txt', '/a/b')).toBe(true);
    expect(pathMatches('/a/b/c.txt', '/a/b/')).toBe(true);
  });

  it('does not treat a sibling prefix as a match', () => {
    expect(pathMatches('/a/bcd.txt', '/a/b')).toBe(false);
  });

  it('supports trailing-star globs', () => {
    expect(pathMatches('/var/cache/x', '/var/cache/*')).toBe(true);
    expect(pathMatches('/var/other', '/var/cache/*')).toBe(false);
  });

  it('normalises backslashes', () => {
    expect(pathMatches('C:\\tmp\\a', 'C:/tmp')).toBe(true);
  });
});

describe('pathMatchesAny', () => {
  it('is true when any pattern matches, false when none do', () => {
    expect(pathMatchesAny('/a/b', ['/x', '/a'])).toBe(true);
    expect(pathMatchesAny('/a/b', ['/x', '/y'])).toBe(false);
  });
});

describe('pathMatches — prefix boundaries (the CVE-2026-58043 class)', () => {
  it('does not let a directory allowlist cover a name-prefix sibling', () => {
    // Granting `~/data` must never grant `~/data-secrets`, which is exactly how
    // Node's own permission model over-granted.
    expect(pathMatches('/home/app/data-secrets/key.pem', '/home/app/data')).toBe(false);
    expect(pathMatches('/home/app/datastore', '/home/app/data')).toBe(false);
    expect(pathMatches('/home/app/data/x.json', '/home/app/data')).toBe(true);
  });

  it('an explicit trailing * is the caller asking for the prefix', () => {
    // Documented behaviour, not a boundary bug: `data*` is a glob the user wrote.
    expect(pathMatches('/home/app/data-secrets/key.pem', '/home/app/data*')).toBe(true);
  });
});
