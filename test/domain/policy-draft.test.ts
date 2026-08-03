import { describe, it, expect } from 'vitest';
import { draftPolicy } from '../../src/domain/policy-draft.js';
import { createEvent, type DhEvent } from '../../src/domain/event.js';

function denied(partial: Partial<Parameters<typeof createEvent>[0]> = {}): DhEvent {
  return createEvent({
    capability: 'fs.read',
    package: 'pkg',
    origin: 'dependency',
    detail: '/home/alice/.npmrc',
    stack: [],
    sensitive: true,
    allowed: false,
    blocked: false,
    reason: 'not allowed',
    timestamp: 0,
    ...partial,
  });
}

const options = { homeDir: '/home/alice' };

describe('draftPolicy', () => {
  it('grants exactly the sensitive path that was read, under ~', () => {
    const draft = draftPolicy([denied()], options);
    expect(draft.policy.packages['pkg']).toEqual({ fs: { read: ['~/.npmrc'] } });
  });

  it('keeps the default bucket denying, so anything unseen stays refused', () => {
    const draft = draftPolicy([denied()], options);
    expect(draft.policy.default).toEqual({
      net: { connect: [] },
      spawn: false,
      env: false,
    });
    expect(draft.policy.mode).toBe('observe');
  });

  it('drafts nothing from calls policy already allowed', () => {
    const allowed = denied({ allowed: false });
    const fine = createEvent({
      capability: 'fs.read',
      package: 'pkg',
      origin: 'dependency',
      detail: '/app/index.js',
      stack: [],
      sensitive: false,
      allowed: true,
      blocked: false,
      timestamp: 0,
    });
    const draft = draftPolicy([allowed, fine], options);
    expect(draft.policy.packages['pkg']).toEqual({ fs: { read: ['~/.npmrc'] } });
  });

  it('turns a connection into a host allowlist entry, not a wildcard', () => {
    const draft = draftPolicy(
      [
        denied({
          capability: 'net.connect',
          detail: 'https://ingest.sentry.io/api/1/store',
          sensitive: false,
        }),
      ],
      options,
    );
    expect(draft.policy.packages['pkg']).toEqual({
      net: { connect: ['ingest.sentry.io'] },
    });
  });

  it('gates DNS behind the same host list as connecting', () => {
    const draft = draftPolicy(
      [
        denied({
          capability: 'net.resolve',
          detail: 'api.example.com',
          sensitive: false,
        }),
      ],
      options,
    );
    expect(draft.policy.packages['pkg']?.net?.connect).toEqual(['api.example.com']);
  });

  it('collects several capabilities for one package', () => {
    const draft = draftPolicy(
      [
        denied({ capability: 'env.read', detail: 'NPM_TOKEN' }),
        denied({ capability: 'fs.write', detail: '/home/alice/.npmrc' }),
        denied({ capability: 'process.spawn', detail: 'sh -c curl', sensitive: true }),
        denied({ capability: 'process.native', detail: '/x/a.node' }),
        denied({ capability: 'code.eval', detail: 'render()' }),
      ],
      options,
    );

    expect(draft.policy.packages['pkg']).toEqual({
      fs: { write: ['~/.npmrc'] },
      spawn: true,
      native: true,
      eval: true,
      env: ['NPM_TOKEN'],
    });
  });

  it('flags the open-ended grants for review, and nothing else', () => {
    const draft = draftPolicy(
      [
        denied({ capability: 'process.spawn', detail: 'sh' }),
        denied({ capability: 'code.eval', detail: 'x' }),
        denied({ capability: 'env.read', detail: 'NPM_TOKEN' }),
      ],
      options,
    );

    expect(draft.notes[0]?.needsReview).toEqual(['process.spawn', 'code.eval']);
  });

  it('records what it saw, so the draft can be reviewed', () => {
    const draft = draftPolicy(
      [denied({ capability: 'env.read', detail: 'NPM_TOKEN' })],
      options,
    );
    expect(draft.notes[0]?.observations).toEqual(['read the secret NPM_TOKEN']);
  });

  it('never grants what it could not attribute', () => {
    const draft = draftPolicy(
      [denied({ package: null, origin: 'unknown', detail: '/home/alice/.ssh/id_rsa' })],
      options,
    );

    expect(draft.policy.packages).toEqual({});
    expect(draft.unattributed).toEqual(['fs.read ~/.ssh/id_rsa']);
  });

  it('does not grant your own code anything either', () => {
    const draft = draftPolicy(
      [denied({ package: null, origin: 'application' })],
      options,
    );
    expect(draft.policy.packages).toEqual({});
  });

  it('deduplicates repeats and sorts, so the file is stable between runs', () => {
    const draft = draftPolicy(
      [
        denied({ package: 'b', detail: '/home/alice/.npmrc' }),
        denied({ package: 'a', capability: 'env.read', detail: 'Z_TOKEN' }),
        denied({ package: 'a', capability: 'env.read', detail: 'A_TOKEN' }),
        denied({ package: 'a', capability: 'env.read', detail: 'Z_TOKEN' }),
      ],
      options,
    );

    expect(Object.keys(draft.policy.packages)).toEqual(['a', 'b']);
    expect(draft.policy.packages['a']?.env).toEqual(['A_TOKEN', 'Z_TOKEN']);
  });

  it('drafts an empty policy from a clean run', () => {
    const draft = draftPolicy([], options);
    expect(draft.policy.packages).toEqual({});
    expect(draft.notes).toEqual([]);
    expect(draft.unattributed).toEqual([]);
  });

  it('leaves paths outside the home directory absolute', () => {
    const draft = draftPolicy([denied({ detail: '/etc/passwd' })], options);
    expect(draft.policy.packages['pkg']?.fs?.read).toEqual(['/etc/passwd']);
  });
});
