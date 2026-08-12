import { describe, it, expect, afterEach } from 'vitest';
import {
  applyModeOverride,
  normalizePolicy,
} from '../../src/adapters/config/normalize-policy.js';
import { RulePolicyEngine } from '../../src/domain/policy-engine.js';
import type { CapabilityRequest } from '../../src/domain/capability-request.js';

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
        reader: { fs: { read: ['/a'], write: ['/b'] } },
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

  it('parses native and eval boolean policies', () => {
    const policy = normalizePolicy({
      packages: { bcrypt: { native: true }, templater: { eval: true } },
    });
    expect(policy.packages['bcrypt']?.native).toBe(true);
    expect(policy.packages['templater']?.eval).toBe(true);
  });

  it('drops non-boolean native/eval fields', () => {
    const policy = normalizePolicy({ default: { native: 'yes', eval: 1 } });
    expect(policy.default.native).toBeUndefined();
    expect(policy.default.eval).toBeUndefined();
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

describe('normalizePolicy — portable fs patterns', () => {
  const home = '/home/alice';

  it('expands a leading ~/ so a committed config works on any machine', () => {
    const policy = normalizePolicy(
      { packages: { pkg: { fs: { read: ['~/.npmrc'], write: ['~/.config/x'] } } } },
      { homeDir: home },
    );

    expect(policy.packages['pkg']?.fs?.read).toEqual(['/home/alice/.npmrc']);
    expect(policy.packages['pkg']?.fs?.write).toEqual(['/home/alice/.config/x']);
  });

  it('expands a bare ~', () => {
    const policy = normalizePolicy(
      { packages: { pkg: { fs: { read: ['~'] } } } },
      { homeDir: home },
    );
    expect(policy.packages['pkg']?.fs?.read).toEqual([home]);
  });

  it('leaves absolute paths and mid-string tildes alone', () => {
    const policy = normalizePolicy(
      { packages: { pkg: { fs: { read: ['/etc/passwd', '/tmp/a~b'] } } } },
      { homeDir: home },
    );
    expect(policy.packages['pkg']?.fs?.read).toEqual(['/etc/passwd', '/tmp/a~b']);
  });

  it('expands in the default bucket too', () => {
    const policy = normalizePolicy(
      { default: { fs: { read: ['~/.npmrc'] } } },
      { homeDir: home },
    );
    expect(policy.default.fs?.read).toEqual(['/home/alice/.npmrc']);
  });
});

describe('normalizePolicy — prototype pollution cannot flip deny-by-default', () => {
  const proto = Object.prototype as unknown as Record<string, unknown>;
  afterEach(() => {
    delete proto['evil'];
    delete proto['spawn'];
  });

  const req = (partial: Partial<CapabilityRequest>): CapabilityRequest => ({
    package: 'evil',
    origin: 'dependency',
    detail: '',
    stack: [],
    capability: 'process.spawn',
    ...partial,
  });

  it('a package cannot inherit an allow-all bucket from Object.prototype', () => {
    const policy = normalizePolicy({
      mode: 'enforce',
      default: { spawn: false },
      packages: {},
    });
    const engine = new RulePolicyEngine(policy);

    // A dependency pollutes the prototype AFTER the policy is built, keyed by its
    // own package name — the packages map must not consult it.
    proto['evil'] = { spawn: true, native: true, eval: true, memory: true };
    expect(
      engine.evaluate(req({ capability: 'process.spawn', detail: 'id' })).allowed,
    ).toBe(false);
  });

  it('a bucket that omits a capability does not inherit true from Object.prototype', () => {
    // `some-lib` is allowlisted for network but says nothing about spawn.
    const policy = normalizePolicy({
      mode: 'enforce',
      default: { spawn: false },
      packages: { 'some-lib': { net: { connect: ['api.example.com'] } } },
    });
    const engine = new RulePolicyEngine(policy);

    proto['spawn'] = true; // pollute the capability key itself
    expect(
      engine.evaluate(
        req({ package: 'some-lib', capability: 'process.spawn', detail: 'id' }),
      ).allowed,
    ).toBe(false);
  });
});
