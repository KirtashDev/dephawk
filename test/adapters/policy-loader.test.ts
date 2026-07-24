import { describe, it, expect, vi } from 'vitest';
import {
  EnvPolicyLoader,
  FileConfigPolicyLoader,
} from '../../src/adapters/config/policy-loader.js';

describe('EnvPolicyLoader', () => {
  it('returns permissive when no policy env is present', async () => {
    const policy = await new EnvPolicyLoader({}).load();
    expect(policy.mode).toBe('observe');
    expect(policy.packages).toEqual({});
  });

  it('parses DEPHAWK_POLICY JSON', async () => {
    const json = JSON.stringify({ mode: 'enforce', packages: { a: { spawn: true } } });
    const policy = await new EnvPolicyLoader({ DEPHAWK_POLICY: json }).load();
    expect(policy.mode).toBe('enforce');
    expect(policy.packages['a']?.spawn).toBe(true);
  });

  it('falls back to permissive on invalid JSON', async () => {
    const policy = await new EnvPolicyLoader({ DEPHAWK_POLICY: '{not json' }).load();
    expect(policy.mode).toBe('observe');
  });

  it('lets DEPHAWK_MODE override the policy mode', async () => {
    const json = JSON.stringify({ mode: 'observe' });
    const policy = await new EnvPolicyLoader({
      DEPHAWK_POLICY: json,
      DEPHAWK_MODE: 'enforce',
    }).load();
    expect(policy.mode).toBe('enforce');
  });
});

describe('FileConfigPolicyLoader', () => {
  it('returns permissive (with mode override) when configPath is null', async () => {
    const policy = await new FileConfigPolicyLoader({
      configPath: null,
      env: { DEPHAWK_MODE: 'enforce' },
    }).load();
    expect(policy.mode).toBe('enforce');
  });

  it('imports a default-exported config', async () => {
    const loader = new FileConfigPolicyLoader({
      configPath: '/x/dephawk.config.js',
      importer: async () => ({
        default: { mode: 'enforce', packages: { z: { env: true } } },
      }),
    });
    const policy = await loader.load();
    expect(policy.mode).toBe('enforce');
    expect(policy.packages['z']?.env).toBe(true);
  });

  it('accepts a module-shaped (non-default) config', async () => {
    const loader = new FileConfigPolicyLoader({
      configPath: '/x/config.js',
      importer: async () => ({ mode: 'enforce' }),
    });
    expect((await loader.load()).mode).toBe('enforce');
  });

  it('degrades to permissive and warns when the import throws', async () => {
    const warn = vi.fn();
    const loader = new FileConfigPolicyLoader({
      configPath: '/x/broken.js',
      importer: async () => {
        throw new Error('boom');
      },
      warn,
    });
    const policy = await loader.load();
    expect(policy.mode).toBe('observe');
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toContain('boom');
  });
});
