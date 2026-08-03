import { describe, it, expect } from 'vitest';
import { renderConfig } from '../../src/adapters/config/render-config.js';
import { normalizePolicy } from '../../src/adapters/config/normalize-policy.js';
import type { PolicyDraft } from '../../src/domain/policy-draft.js';

const draft: PolicyDraft = {
  policy: {
    mode: 'observe',
    default: { net: { connect: [] }, spawn: false, env: false },
    packages: {
      '@sentry/node': { net: { connect: ['ingest.sentry.io'] }, env: ['SENTRY_DSN'] },
      sharp: { native: true },
      tool: { fs: { read: ['~/.npmrc'], write: ['/var/log/app/'] }, spawn: true },
    },
  },
  notes: [
    {
      package: '@sentry/node',
      observations: ['connected to ingest.sentry.io'],
      needsReview: [],
    },
    {
      package: 'sharp',
      observations: ['loaded a native addon'],
      needsReview: ['process.native'],
    },
    {
      package: 'tool',
      observations: ['spawned convert'],
      needsReview: ['process.spawn'],
    },
  ],
  unattributed: ['fs.read ~/.ssh/id_rsa'],
};

describe('renderConfig', () => {
  const source = renderConfig(draft);

  it('says up front that it granted what happened, not what is safe', () => {
    expect(source).toContain('because it HAPPENED');
    expect(source).toContain('Read it before you trust it');
  });

  it('lists the open-ended grants where a reviewer will see them', () => {
    expect(source).toContain('sharp: process.native');
    expect(source).toContain('tool: process.spawn');
    // A bounded host allowlist is not in that list.
    expect(source).not.toContain('@sentry/node: ');
  });

  it('reports what it refused to grant, and why it refused', () => {
    expect(source).toContain('could not attribute');
    expect(source).toContain('fs.read ~/.ssh/id_rsa');
  });

  it('annotates each package with what it was seen doing', () => {
    expect(source).toContain('// connected to ingest.sentry.io');
    expect(source).toContain('// spawned convert');
  });

  it('quotes a scoped package name and leaves a plain one bare', () => {
    expect(source).toContain("'@sentry/node': {");
    expect(source).toContain('sharp: {');
  });

  it('round-trips: what it writes is what the loader reads back', async () => {
    // The file is JavaScript, so evaluate it the way the loader would.
    const module = (await import(
      `data:text/javascript,${encodeURIComponent(source)}`
    )) as { default: unknown };

    const parsed = normalizePolicy(module.default, { homeDir: '/home/alice' });

    expect(parsed.mode).toBe('observe');
    expect(parsed.default).toEqual({ net: { connect: [] }, spawn: false, env: false });
    expect(parsed.packages['@sentry/node']).toEqual({
      net: { connect: ['ingest.sentry.io'] },
      env: ['SENTRY_DSN'],
    });
    expect(parsed.packages['sharp']).toEqual({ native: true });
    // `~` is expanded on load, so the committed file stays portable.
    expect(parsed.packages['tool']?.fs?.read).toEqual(['/home/alice/.npmrc']);
    expect(parsed.packages['tool']?.fs?.write).toEqual(['/var/log/app/']);
  });

  it('renders a clean run as an empty but valid policy', async () => {
    const empty = renderConfig({
      policy: { mode: 'observe', default: {}, packages: {} },
      notes: [],
      unattributed: [],
    });
    expect(empty).toContain('Nothing needed a rule');

    const module = (await import(
      `data:text/javascript,${encodeURIComponent(empty)}`
    )) as { default: unknown };
    expect(normalizePolicy(module.default).packages).toEqual({});
  });

  it('escapes a quote in a value rather than producing broken source', async () => {
    const nasty = renderConfig({
      policy: {
        mode: 'observe',
        default: {},
        packages: { evil: { fs: { read: ["/tmp/it's here"] } } },
      },
      notes: [],
      unattributed: [],
    });

    const module = (await import(
      `data:text/javascript,${encodeURIComponent(nasty)}`
    )) as { default: unknown };
    expect(normalizePolicy(module.default).packages['evil']?.fs?.read).toEqual([
      "/tmp/it's here",
    ]);
  });
});
