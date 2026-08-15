import { describe, it, expect } from 'vitest';
import { RulePolicyEngine } from '../../src/domain/policy-engine.js';
import type { Policy } from '../../src/domain/policy.js';
import type { CapabilityRequest } from '../../src/domain/capability-request.js';

function req(
  partial: Partial<CapabilityRequest> & Pick<CapabilityRequest, 'capability'>,
): CapabilityRequest {
  return {
    package: 'some-pkg',
    origin: 'dependency',
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
  it('always allows the user’s own code', () => {
    const v = engine.evaluate(
      req({
        capability: 'fs.read',
        package: null,
        origin: 'application',
        detail: '/home/alice/.ssh/id_rsa',
      }),
    );
    expect(v.allowed).toBe(true);
    expect(v.sensitive).toBe(true);
  });
});

describe('RulePolicyEngine — unattributed calls', () => {
  // A call nobody owns is not the same as a call you own: it is what a
  // dependency laundering itself across an async boundary looks like. It gets
  // the default bucket, not the benefit of the doubt.
  it('holds an unknown origin to the default policy instead of allowing it', () => {
    const v = engine.evaluate(
      req({
        capability: 'fs.read',
        package: null,
        origin: 'unknown',
        detail: '/home/alice/.ssh/id_rsa',
      }),
    );
    expect(v.allowed).toBe(false);
    expect(v.sensitive).toBe(true);
    expect(v.reason).toContain('/home/alice/.ssh/id_rsa');
  });

  it('still allows mundane calls from an unknown origin', () => {
    const v = engine.evaluate(
      req({
        capability: 'fs.read',
        package: null,
        origin: 'unknown',
        detail: '/app/src/index.js',
      }),
    );
    expect(v.allowed).toBe(true);
    expect(v.sensitive).toBe(false);
  });

  it('denies an unattributed spawn, matching the default bucket', () => {
    const v = engine.evaluate(
      req({
        capability: 'process.spawn',
        package: null,
        origin: 'unknown',
        detail: 'sh',
      }),
    );
    expect(v.allowed).toBe(false);
  });
});

describe('RulePolicyEngine — dephawk’s own audit log', () => {
  const sink = '/tmp/dephawk-guard-a1b2/events.jsonl';
  const guarded = new RulePolicyEngine(policy, [sink]);

  it('refuses a write to the sink, mandatorily — even in observe mode', () => {
    const v = guarded.evaluate(req({ capability: 'fs.write', detail: sink }));
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBe(true);
    expect(v.reason).toContain('audit log');
  });

  it('refuses it for the application too — this is not policy about your code', () => {
    const v = guarded.evaluate(
      req({ capability: 'fs.write', package: null, origin: 'application', detail: sink }),
    );
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBe(true);
  });

  it('refuses removing the directory that holds it', () => {
    const v = guarded.evaluate(
      req({ capability: 'fs.write', detail: '/tmp/dephawk-guard-a1b2' }),
    );
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBe(true);
  });

  it('leaves reads alone — the path is in DEPHAWK_SINK anyway', () => {
    const v = guarded.evaluate(req({ capability: 'fs.read', detail: sink }));
    expect(v.allowed).toBe(true);
  });

  it('does not affect an engine with no protected paths', () => {
    const v = engine.evaluate(req({ capability: 'fs.write', detail: sink }));
    expect(v.allowed).toBe(true);
    expect(v.mandatory).toBeUndefined();
  });

  it('leaves ordinary policy denials non-mandatory', () => {
    const v = guarded.evaluate(
      req({ capability: 'fs.write', detail: '/home/alice/.npmrc' }),
    );
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBeUndefined();
  });
});

describe('RulePolicyEngine — dephawk’s own config (planting for the next run)', () => {
  // No protected paths at all: on a run with no config, the config's absolute
  // path is unknown, so the basename check must stand on its own.
  const bare = new RulePolicyEngine(policy, []);

  it('refuses a dependency writing dephawk.config.js, mandatorily', () => {
    const v = bare.evaluate(
      req({ capability: 'fs.write', detail: '/repo/dephawk.config.js' }),
    );
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBe(true);
    expect(v.reason).toContain('config');
  });

  it('refuses it for the application origin too', () => {
    const v = bare.evaluate(
      req({
        capability: 'fs.write',
        package: null,
        origin: 'application',
        detail: '/repo/dephawk.config.mjs',
      }),
    );
    expect(v.allowed).toBe(false);
    expect(v.mandatory).toBe(true);
  });

  it('leaves reads of the config alone', () => {
    const v = bare.evaluate(
      req({ capability: 'fs.read', detail: '/repo/dephawk.config.js' }),
    );
    expect(v.allowed).toBe(true);
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

  it('treats writing a shell startup file as sensitive persistence', () => {
    const rc = engine.evaluate(
      req({ capability: 'fs.write', detail: '/home/alice/.bashrc' }),
    );
    expect(rc.sensitive).toBe(true);
    expect(rc.allowed).toBe(false);

    // Reading it is not sensitive — persistence is a write-side concern.
    const read = engine.evaluate(
      req({ capability: 'fs.read', detail: '/home/alice/.bashrc' }),
    );
    expect(read.sensitive).toBe(false);
    expect(read.allowed).toBe(true);
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

describe('RulePolicyEngine — writing into another package’s directory', () => {
  const engine = new RulePolicyEngine(policy);

  it('refuses one package writing into another, whatever the filename', () => {
    // The takeover: code planted here runs as `innocent` and inherits whatever
    // policy grants it, and the path itself is entirely ordinary.
    const verdict = engine.evaluate(
      req({
        capability: 'fs.write',
        package: 'evil',
        detail: '/proj/node_modules/innocent/.cache.js',
      }),
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.sensitive).toBe(true);
    expect(verdict.reason).toMatch(/another package/);
  });

  it('refuses it even when the writer has a write allowlist of its own', () => {
    // Being trusted with your own paths must not buy the right to overwrite a
    // sibling dependency.
    const verdict = engine.evaluate(
      req({
        capability: 'fs.write',
        package: 'log-writer',
        detail: '/proj/node_modules/innocent/index.js',
      }),
    );
    expect(verdict.allowed).toBe(false);
  });

  it('allows a package writing inside its own directory', () => {
    const verdict = engine.evaluate(
      req({
        capability: 'fs.write',
        package: 'sharp',
        detail: '/proj/node_modules/sharp/build/Release/sharp.node',
      }),
    );
    expect(verdict.allowed).toBe(true);
  });

  it('leaves the application free to write into node_modules', () => {
    // patch-package, monorepo linkers and build steps all do this.
    const verdict = engine.evaluate(
      req({
        capability: 'fs.write',
        package: null,
        origin: 'application',
        detail: '/proj/node_modules/innocent/index.js',
      }),
    );
    expect(verdict.allowed).toBe(true);
  });
});
