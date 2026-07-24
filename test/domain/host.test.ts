import { describe, it, expect } from 'vitest';
import { extractHost, hostMatches, hostMatchesAny } from '../../src/domain/host.js';

describe('extractHost', () => {
  it.each([
    ['https://api.example.com/v1/collect', 'api.example.com'],
    ['http://example.com', 'example.com'],
    ['example.com:443', 'example.com'],
    ['example.com', 'example.com'],
    ['https://user:pass@secret.example.com:8443/x', 'secret.example.com'],
    ['API.Example.COM', 'api.example.com'],
    ['https://[2001:db8::1]:443/path', '2001:db8::1'],
    ['[::1]:8080', '::1'],
  ])('extracts host from %s', (input, expected) => {
    expect(extractHost(input)).toBe(expected);
  });

  it('trims whitespace', () => {
    expect(extractHost('  example.com  ')).toBe('example.com');
  });
});

describe('hostMatches', () => {
  it('matches exact hosts case-insensitively', () => {
    expect(hostMatches('api.example.com', 'API.example.com')).toBe(true);
    expect(hostMatches('api.example.com', 'other.com')).toBe(false);
  });

  it('matches prefix globs against apex and subdomains', () => {
    expect(hostMatches('example.com', '*.example.com')).toBe(true);
    expect(hostMatches('a.example.com', '*.example.com')).toBe(true);
    expect(hostMatches('a.b.example.com', '*.example.com')).toBe(true);
  });

  it('does not let a glob match a different domain', () => {
    expect(hostMatches('evil-example.com', '*.example.com')).toBe(false);
    expect(hostMatches('example.com.evil.com', '*.example.com')).toBe(false);
  });
});

describe('hostMatchesAny', () => {
  it('is true when any pattern matches', () => {
    expect(hostMatchesAny('a.example.com', ['other.com', '*.example.com'])).toBe(true);
  });
  it('is false for an empty allowlist', () => {
    expect(hostMatchesAny('a.example.com', [])).toBe(false);
  });
});
