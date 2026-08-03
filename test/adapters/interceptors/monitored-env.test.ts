import { describe, it, expect } from 'vitest';
import {
  captureMonitoringEnv,
  restoreMonitoring,
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
