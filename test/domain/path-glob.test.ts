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
