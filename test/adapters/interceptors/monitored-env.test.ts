import { describe, it, expect } from 'vitest';
import { SHARE_ENV } from 'node:worker_threads';
import {
  captureMonitoringEnv,
  restoreMonitoring,
  restoreWorkerOptions,
} from '../../../src/adapters/interceptors/monitored-env.js';

const REGISTER = 'file:///app/node_modules/dephawk/dist/register.js';

const started: NodeJS.ProcessEnv = {
  NODE_OPTIONS: `--import ${REGISTER}`,
  DEPHAWK_POLICY: '{"mode":"observe"}',
  DEPHAWK_SINK: '/tmp/dephawk-guard-x/events.jsonl',
  PATH: '/usr/bin',
  HOME: '/home/alice',
};

describe('captureMonitoringEnv', () => {
  it('picks up the --import flag and every DEPHAWK_ variable', () => {
    const monitoring = captureMonitoringEnv(started);

    expect(monitoring.imports).toEqual([`--import ${REGISTER}`]);
    expect(monitoring.variables).toEqual({
      DEPHAWK_POLICY: '{"mode":"observe"}',
      DEPHAWK_SINK: '/tmp/dephawk-guard-x/events.jsonl',
    });
    expect(monitoring.variables).not.toHaveProperty('PATH');
  });

  it('accepts the --import=url spelling', () => {
    const monitoring = captureMonitoringEnv({ NODE_OPTIONS: `--import=${REGISTER}` });
    expect(monitoring.imports).toEqual([`--import=${REGISTER}`]);
  });

  it('keeps other NODE_OPTIONS flags out of the required set', () => {
    const monitoring = captureMonitoringEnv({
      NODE_OPTIONS: `--max-old-space-size=4096 --import ${REGISTER}`,
    });
    expect(monitoring.imports).toEqual([`--import ${REGISTER}`]);
  });

  it('falls back to the register URL when --import came from the command line', () => {
    const monitoring = captureMonitoringEnv({}, REGISTER);
    expect(monitoring.imports).toEqual([`--import ${REGISTER}`]);
  });

  it('does not duplicate a register URL already present in NODE_OPTIONS', () => {
    const monitoring = captureMonitoringEnv(started, REGISTER);
    expect(monitoring.imports).toHaveLength(1);
  });

  it('requires nothing when dephawk was never in the environment', () => {
    const monitoring = captureMonitoringEnv({ PATH: '/usr/bin' });
    expect(monitoring.imports).toEqual([]);
    expect(monitoring.variables).toEqual({});
  });
});

describe('restoreMonitoring', () => {
  const monitoring = captureMonitoringEnv(started);

  it('puts back everything a sanitised environment dropped', () => {
    const { env, restored } = restoreMonitoring({ PATH: '/usr/bin' }, monitoring);

    expect(env['NODE_OPTIONS']).toBe(`--import ${REGISTER}`);
    expect(env['DEPHAWK_POLICY']).toBe('{"mode":"observe"}');
    expect(env['DEPHAWK_SINK']).toBe('/tmp/dephawk-guard-x/events.jsonl');
    expect(restored).toEqual(['DEPHAWK_POLICY', 'DEPHAWK_SINK', 'NODE_OPTIONS']);
    // Whatever else the caller wanted is left exactly as it was.
    expect(env['PATH']).toBe('/usr/bin');
  });

  it('reports nothing restored when the child already carries monitoring', () => {
    const { restored } = restoreMonitoring(started, monitoring);
    expect(restored).toEqual([]);
  });

  it('keeps the caller’s own NODE_OPTIONS flags and appends ours', () => {
    const { env } = restoreMonitoring(
      { NODE_OPTIONS: '--max-old-space-size=4096' },
      monitoring,
    );

    expect(env['NODE_OPTIONS']).toBe(`--max-old-space-size=4096 --import ${REGISTER}`);
  });

  it('catches a substituted DEPHAWK value, not just a deleted one', () => {
    const { env, restored } = restoreMonitoring(
      { ...started, DEPHAWK_POLICY: '{"mode":"observe","packages":{"evil":{}}}' },
      monitoring,
    );

    expect(env['DEPHAWK_POLICY']).toBe('{"mode":"observe"}');
    expect(restored).toEqual(['DEPHAWK_POLICY']);
  });

  it('does not mutate the environment it was given', () => {
    const childEnv: NodeJS.ProcessEnv = { PATH: '/usr/bin' };
    restoreMonitoring(childEnv, monitoring);
    expect(childEnv).toEqual({ PATH: '/usr/bin' });
  });

  it('leaves an environment alone when there is nothing to enforce', () => {
    const empty = captureMonitoringEnv({});
    const { env, restored } = restoreMonitoring({ PATH: '/usr/bin' }, empty);

    expect(env).toEqual({ PATH: '/usr/bin' });
    expect(restored).toEqual([]);
  });
});

describe('restoreWorkerOptions', () => {
  // A worker declines inheritance through two doors: an emptied `execArgv`
  // (no --import) and an emptied `env` (no NODE_OPTIONS). Either one used to buy
  // a completely unmonitored thread.
  const monitoring = captureMonitoringEnv(started);

  it('puts --import back into an emptied execArgv, as one argv element', () => {
    const { options, restored } = restoreWorkerOptions({ execArgv: [] }, monitoring);

    // `--import <url>` is legal in NODE_OPTIONS but not as a single argv entry.
    expect(options['execArgv']).toEqual([`--import=${REGISTER}`]);
    expect(restored).toEqual(['execArgv']);
  });

  it('keeps the caller’s own flags alongside it', () => {
    const { options } = restoreWorkerOptions(
      { execArgv: ['--trace-warnings'] },
      monitoring,
    );

    expect(options['execArgv']).toEqual(['--trace-warnings', `--import=${REGISTER}`]);
  });

  it.each([
    [[`--import=${REGISTER}`]],
    // The two-element spelling names the same module and counts too.
    [['--import', REGISTER]],
  ])('adds nothing when execArgv already carries it: %s', (execArgv) => {
    expect(restoreWorkerOptions({ execArgv }, monitoring).restored).toEqual([]);
  });

  it('restores monitoring in an emptied env', () => {
    const { options, restored } = restoreWorkerOptions({ env: {} }, monitoring);

    expect(options['env']).toEqual({
      NODE_OPTIONS: `--import ${REGISTER}`,
      DEPHAWK_POLICY: '{"mode":"observe"}',
      DEPHAWK_SINK: '/tmp/dephawk-guard-x/events.jsonl',
    });
    expect(restored).toContain('NODE_OPTIONS');
    expect(restored).toContain('DEPHAWK_SINK');
  });

  it('leaves inherited options alone: absent means inherit, and inheriting is fine', () => {
    const { options, restored } = restoreWorkerOptions({ name: 'w1' }, monitoring);

    expect(options).toEqual({ name: 'w1' });
    expect(restored).toEqual([]);
  });

  it('does not treat SHARE_ENV as an environment to patch', () => {
    // It is a symbol, and it shares the parent's environment — which is monitored.
    const { restored } = restoreWorkerOptions({ env: SHARE_ENV }, monitoring);
    expect(restored).toEqual([]);
  });

  it('does not mutate the options it was given', () => {
    const original = { execArgv: [], env: {} };
    restoreWorkerOptions(original, monitoring);
    expect(original).toEqual({ execArgv: [], env: {} });
  });
});
