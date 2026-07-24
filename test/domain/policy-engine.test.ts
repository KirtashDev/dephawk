import { describe, it, expect } from 'vitest';
import { RulePolicyEngine } from '../../src/domain/policy-engine.js';
import type { Policy } from '../../src/domain/policy.js';
import type { CapabilityRequest } from '../../src/domain/capability-request.js';

function req(
  partial: Partial<CapabilityRequest> & Pick<CapabilityRequest, 'capability'>,
): CapabilityRequest {
  return {
    package: 'some-pkg',
    detail: '',
    stack: [],
    ...partial,
  };
}

const policy: Policy = {
  mode: 'enforce',
  default: { net: { connect: [] }, spawn: false, env: false },
  packages: {
    'image-optimizer': { spawn: true },
    '@sentry/node': { net: { connect: ['*.sentry.io'] }, env: ['SENTRY_DSN'] },
    'log-writer': { fs: { write: ['/var/log/app/'] } },
    'config-reader': { fs: { read: ['/home/alice/.npmrc'] } },
  },
};

const engine = new RulePolicyEngine(policy);

describe('RulePolicyEngine — app code', () => {
  it('always allows the user’s own code (package null)', () => {
    const v = engine.evaluate(
      req({ capability: 'fs.read', package: null, detail: '/home/alice/.ssh/id_rsa' }),
    );
    expect(v.allowed).toBe(true);
    expect(v.sensitive).toBe(true);
  });
});

describe('RulePolicyEngine — net.connect', () => {
  it('blocks connections not in the allowlist', () => {
    const v = engine.evaluate(
      req({ capability: 'net.connect', detail: 'https://collector.sketchy.ru' }),
    );
    expect(v.allowed).toBe(false);
    expect(v.sensitive).toBe(false);
    expect(v.reason).toContain('collector.sketchy.ru');
  });

  it('allows allowlisted hosts including subdomains', () => {
    const v = engine.evaluate(
      req({
        capability: 'net.connect',
        package: '@sentry/node',
        detail: 'https://ingest.sentry.io/api',
      }),
    );
    expect(v.allowed).toBe(true);
  });

  it('matches a udp:// detail against the host allowlist (raw UDP gated like HTTP)', () => {
    const e = new RulePolicyEngine({
      ...policy,
      packages: { metrics: { net: { connect: ['metrics.example.com'] } } },
    });
    const allowed = e.evaluate(
      req({
        capability: 'net.connect',
        package: 'metrics',
        detail: 'udp://metrics.example.com:8125',
      }),
    );
    expect(allowed.allowed).toBe(true);

    const denied = e.evaluate(
      req({
        capability: 'net.connect',
        package: 'metrics',
        detail: 'udp://evil.example.org:8125',
      }),
    );
    expect(denied.allowed).toBe(false);
  });
});

describe('RulePolicyEngine — net.resolve (DNS)', () => {
  it('blocks resolution of hosts not in the connect allowlist', () => {
    const v = engine.evaluate(
      req({ capability: 'net.resolve', detail: 'evil.attacker.com' }),
    );
    expect(v.allowed).toBe(false);
    expect(v.sensitive).toBe(false);
    expect(v.reason).toContain('evil.attacker.com');
  });

  it('allows resolution of allowlisted hosts (shares the net.connect allowlist)', () => {
    const v = engine.evaluate(
      req({
        capability: 'net.resolve',
        package: '@sentry/node',
        detail: 'ingest.sentry.io',
      }),
    );
    expect(v.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — process.native', () => {
  it('is always sensitive and blocked by default', () => {
    const v = engine.evaluate(
      req({ capability: 'process.native', detail: '/x/addon.node' }),
    );
    expect(v.sensitive).toBe(true);
    expect(v.allowed).toBe(false);
    expect(v.reason).toContain('addon.node');
  });

  it('is allowed for packages that opt in', () => {
    const e = new RulePolicyEngine({ ...policy, packages: { bcrypt: { native: true } } });
    const v = e.evaluate(
      req({ capability: 'process.native', package: 'bcrypt', detail: '/x/bcrypt.node' }),
    );
    expect(v.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — code.eval', () => {
  it('is always sensitive and blocked by default', () => {
    const v = engine.evaluate(req({ capability: 'code.eval', detail: 'atob("...")' }));
    expect(v.sensitive).toBe(true);
    expect(v.allowed).toBe(false);
  });

  it('is allowed for packages that opt in', () => {
    const e = new RulePolicyEngine({
      ...policy,
      packages: { templater: { eval: true } },
    });
    const v = e.evaluate(
      req({ capability: 'code.eval', package: 'templater', detail: 'render()' }),
    );
    expect(v.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — process.spawn', () => {
  it('is always sensitive and blocked by default', () => {
    const v = engine.evaluate(
      req({ capability: 'process.spawn', detail: '/bin/sh -c curl' }),
    );
    expect(v.sensitive).toBe(true);
    expect(v.allowed).toBe(false);
  });

  it('is allowed for packages that opt in', () => {
    const v = engine.evaluate(
      req({ capability: 'process.spawn', package: 'image-optimizer', detail: 'convert' }),
    );
    expect(v.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — env.read', () => {
  it('allows mundane env reads', () => {
    const v = engine.evaluate(req({ capability: 'env.read', detail: 'NODE_ENV' }));
    expect(v.sensitive).toBe(false);
    expect(v.allowed).toBe(true);
  });

  it('blocks secret env reads by default', () => {
    const v = engine.evaluate(req({ capability: 'env.read', detail: 'NPM_TOKEN' }));
    expect(v.sensitive).toBe(true);
    expect(v.allowed).toBe(false);
  });

  it('allows secrets named in a package allowlist but not others', () => {
    const allowed = engine.evaluate(
      req({ capability: 'env.read', package: '@sentry/node', detail: 'SENTRY_DSN' }),
    );
    expect(allowed.allowed).toBe(true);

    const denied = engine.evaluate(
      req({
        capability: 'env.read',
        package: '@sentry/node',
        detail: 'AWS_SECRET_ACCESS_KEY',
      }),
    );
    expect(denied.allowed).toBe(false);
  });

  it('allows any secret when env policy is true', () => {
    const engineOpen = new RulePolicyEngine({
      ...policy,
      packages: { trusted: { env: true } },
    });
    const v = engineOpen.evaluate(
      req({ capability: 'env.read', package: 'trusted', detail: 'NPM_TOKEN' }),
    );
    expect(v.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — fs.read / fs.write', () => {
  it('allows mundane reads and blocks sensitive ones by default', () => {
    expect(
      engine.evaluate(req({ capability: 'fs.read', detail: '/app/index.js' })).allowed,
    ).toBe(true);
    const secret = engine.evaluate(
      req({ capability: 'fs.read', detail: '/home/alice/.ssh/id_rsa' }),
    );
    expect(secret.sensitive).toBe(true);
    expect(secret.allowed).toBe(false);
  });

  it('respects an fs.read allowlist', () => {
    const v = engine.evaluate(
      req({
        capability: 'fs.read',
        package: 'config-reader',
        detail: '/home/alice/.npmrc',
      }),
    );
    expect(v.allowed).toBe(true);
  });

  it('allows mundane writes and blocks sensitive ones unless allowlisted', () => {
    expect(
      engine.evaluate(req({ capability: 'fs.write', detail: '/tmp/out.json' })).allowed,
    ).toBe(true);
    const denied = engine.evaluate(
      req({ capability: 'fs.write', detail: '/home/alice/.ssh/authorized_keys' }),
    );
    expect(denied.allowed).toBe(false);

    const allowed = engine.evaluate(
      req({
        capability: 'fs.write',
        package: 'log-writer',
        detail: '/var/log/app/x.log',
      }),
    );
    // /var/log/app is not sensitive, so it's allowed regardless — assert it stays allowed.
    expect(allowed.allowed).toBe(true);
  });
});

describe('RulePolicyEngine — os.info', () => {
  it('is recorded but never blocked', () => {
    const v = engine.evaluate(req({ capability: 'os.info', detail: 'userInfo' }));
    expect(v.allowed).toBe(true);
    expect(v.sensitive).toBe(false);
  });
});

describe('RulePolicyEngine — unlisted package falls back to default', () => {
  it('uses the default bucket for unknown packages', () => {
    const v = engine.evaluate(
      req({ capability: 'net.connect', package: 'random-lib', detail: 'https://x.com' }),
    );
    expect(v.allowed).toBe(false);
  });
});
