import { describe, it, expect } from 'vitest';
import {
  applyModeOverride,
  normalizePolicy,
} from '../../src/adapters/config/normalize-policy.js';

describe('normalizePolicy', () => {
  it('falls back to permissive for non-objects', () => {
    expect(normalizePolicy(null).mode).toBe('observe');
    expect(normalizePolicy(42).packages).toEqual({});
    expect(normalizePolicy([1, 2]).default).toEqual({});
  });

  it('parses a full valid config', () => {
    const policy = normalizePolicy({
      mode: 'enforce',
      default: { net: { connect: [] }, spawn: false, env: false },
      packages: {
        'image-optimizer': { spawn: true },
        '@sentry/node': { net: { connect: ['*.sentry.io'] }, env: ['SENTRY_DSN'] },
        'reader': { fs: { read: ['/a'], write: ['/b'] } },
      },
    });
    expect(policy.mode).toBe('enforce');
    expect(policy.default.spawn).toBe(false);
    expect(policy.packages['image-optimizer']?.spawn).toBe(true);
    expect(policy.packages['@sentry/node']?.net?.connect).toEqual(['*.sentry.io']);
    expect(policy.packages['@sentry/node']?.env).toEqual(['SENTRY_DSN']);
    expect(policy.packages['reader']?.fs).toEqual({ read: ['/a'], write: ['/b'] });
  });

  it('drops malformed fields', () => {
    const policy = normalizePolicy({
      mode: 'nonsense',
      default: { spawn: 'yes', env: 123, net: 'bad', fs: 5 },
      packages: 'not-an-object',
    });
    expect(policy.mode).toBe('observe'); // invalid mode -> default
    expect(policy.default.spawn).toBeUndefined();
    expect(policy.default.env).toBeUndefined();
    expect(policy.default.net).toBeUndefined();
    expect(policy.packages).toEqual({});
  });

  it('accepts boolean and array env policies', () => {
    expect(normalizePolicy({ default: { env: true } }).default.env).toBe(true);
    expect(normalizePolicy({ default: { env: ['A', 1, 'B'] } }).default.env).toEqual([
      'A',
      'B',
    ]);
  });

  it('normalises an empty net object', () => {
    expect(normalizePolicy({ default: { net: {} } }).default.net).toEqual({});
  });
});

describe('applyModeOverride', () => {
  const base = normalizePolicy({ mode: 'observe' });

  it('overrides with a valid mode', () => {
    expect(applyModeOverride(base, 'enforce').mode).toBe('enforce');
  });

  it('ignores an invalid or missing mode', () => {
    expect(applyModeOverride(base, 'bogus').mode).toBe('observe');
    expect(applyModeOverride(base, undefined).mode).toBe('observe');
  });
});
