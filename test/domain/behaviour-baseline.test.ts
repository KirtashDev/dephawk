import { describe, it, expect } from 'vitest';
import {
  canonicalDetail,
  diffBaseline,
  parseBaseline,
  recordBaseline,
  serializeBaseline,
  type Baseline,
} from '../../src/domain/behaviour-baseline.js';
import { createEvent, type DhEvent } from '../../src/domain/event.js';

function ev(partial: Partial<Parameters<typeof createEvent>[0]> = {}): DhEvent {
  return createEvent({
    capability: 'net.resolve',
    package: 'httpclient',
    origin: 'dependency',
    detail: 'api.example.com',
    stack: [],
    sensitive: false,
    allowed: true,
    blocked: false,
    timestamp: 0,
    ...partial,
  });
}

const options = {
  rootPath: '/home/alice/proj',
  homeDir: '/home/alice',
  recordedAt: '2026-08-03T00:00:00.000Z',
};

describe('recordBaseline', () => {
  it('records what a run did, including calls policy allowed', () => {
    // The distinction from a policy: an allowed call is still a behaviour, and
    // a package quietly gaining a new one is the change worth seeing.
    const baseline = recordBaseline([ev()], options);

    expect(baseline.behaviours).toEqual([
      {
        package: 'httpclient',
        origin: 'dependency',
        capability: 'net.resolve',
        detail: 'api.example.com',
      },
    ]);
  });

  it('deduplicates and sorts, so two runs of the same code match byte for byte', () => {
    const a = recordBaseline([ev(), ev({ package: 'zeta' }), ev()], options);
    const b = recordBaseline([ev({ package: 'zeta' }), ev()], options);

    expect(serializeBaseline(a)).toBe(serializeBaseline(b));
    expect(a.behaviours.map((x) => x.package)).toEqual(['httpclient', 'zeta']);
  });

  it('keeps no counts or per-event timestamps, which vary between runs', () => {
    const once = recordBaseline([ev()], options);
    const twice = recordBaseline([ev(), ev({ timestamp: 999 })], options);

    expect(serializeBaseline(once)).toBe(serializeBaseline(twice));
  });

  it('distinguishes unattributed behaviour from your own code', () => {
    const baseline = recordBaseline(
      [
        ev({ package: null, origin: 'application' }),
        ev({ package: null, origin: 'unknown' }),
      ],
      options,
    );
    expect(baseline.behaviours).toHaveLength(2);
  });
});

describe('canonicalDetail', () => {
  it('rewrites the project root to ., so another checkout matches', () => {
    expect(canonicalDetail('/home/alice/proj/src/.env', options)).toBe('./src/.env');
  });

  it('prefers the project root over the home directory', () => {
    // The checkout lives inside ~, and "./src/.env" is the useful spelling.
    expect(canonicalDetail('/home/alice/proj/.npmrc', options)).toBe('./.npmrc');
  });

  it('rewrites the home directory for paths outside the project', () => {
    expect(canonicalDetail('/home/alice/.ssh/id_rsa', options)).toBe('~/.ssh/id_rsa');
  });

  it('leaves anything else alone', () => {
    expect(canonicalDetail('/etc/passwd', options)).toBe('/etc/passwd');
    expect(canonicalDetail('api.example.com', options)).toBe('api.example.com');
  });

  it('does nothing without a root or home to strip', () => {
    expect(canonicalDetail('/home/alice/proj/.npmrc', {})).toBe(
      '/home/alice/proj/.npmrc',
    );
  });
});

describe('diffBaseline', () => {
  const baseline = recordBaseline([ev()], options);

  it('reports nothing when the run is unchanged', () => {
    const diff = diffBaseline(baseline, [ev()], options);

    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
  });

  it('reports a behaviour the baseline never had', () => {
    const diff = diffBaseline(
      baseline,
      [ev(), ev({ detail: 'telemetry.vendor.example' })],
      options,
    );

    expect(diff.added.map((x) => x.detail)).toEqual(['telemetry.vendor.example']);
    expect(diff.removed).toEqual([]);
  });

  it('notices a change of capability by the same package', () => {
    const diff = diffBaseline(
      baseline,
      [ev(), ev({ capability: 'fs.read', detail: '/home/alice/proj/.npmrc' })],
      options,
    );

    expect(diff.added.map((x) => x.capability)).toEqual(['fs.read']);
  });

  it('notices the same behaviour moving to a different package', () => {
    const diff = diffBaseline(baseline, [ev({ package: 'other' })], options);

    expect(diff.added.map((x) => x.package)).toEqual(['other']);
    expect(diff.removed.map((x) => x.package)).toEqual(['httpclient']);
  });

  it('reports what the baseline had and this run did not', () => {
    const diff = diffBaseline(baseline, [], options);

    expect(diff.added).toEqual([]);
    expect(diff.removed).toHaveLength(1);
  });

  it('matches across checkouts, which is the point of committing it', () => {
    const here = recordBaseline(
      [ev({ capability: 'fs.read', detail: '/a/proj/.npmrc' })],
      {
        rootPath: '/a/proj',
      },
    );
    const diff = diffBaseline(
      here,
      [ev({ capability: 'fs.read', detail: '/somewhere/else/.npmrc' })],
      { rootPath: '/somewhere/else' },
    );

    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
  });
});

describe('parseBaseline', () => {
  const written = serializeBaseline(recordBaseline([ev()], options));

  it('round-trips what it wrote', () => {
    expect(parseBaseline(written)).toEqual(recordBaseline([ev()], options));
  });

  it('rejects anything that is not a baseline, rather than comparing to nothing', () => {
    // Silently treating a broken file as empty would report "no change" for a
    // run nobody actually checked.
    expect(parseBaseline('not json')).toBeNull();
    expect(parseBaseline('{}')).toBeNull();
    expect(parseBaseline('[]')).toBeNull();
    expect(parseBaseline(JSON.stringify({ version: 99, behaviours: [] }))).toBeNull();
    expect(parseBaseline(JSON.stringify({ version: 1 }))).toBeNull();
  });

  it('drops malformed entries but keeps the file usable', () => {
    const parsed = parseBaseline(
      JSON.stringify({
        version: 1,
        recordedAt: 'x',
        behaviours: [
          { nonsense: true },
          written ? JSON.parse(written).behaviours[0] : null,
        ],
      }),
    ) as Baseline;

    expect(parsed.behaviours).toHaveLength(1);
  });
});
