import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const demoDir = resolve('examples/demo');
const reportPath = resolve(demoDir, '.dephawk/report.html');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  report: string;
}

function runDemo(mode: 'observe' | 'enforce'): RunResult {
  const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'index.js'], {
    cwd: demoDir,
    encoding: 'utf8',
    env: {
      ...process.env,
      DEPHAWK_MODE: mode,
      NPM_TOKEN: 'demo-secret-token',
      NO_COLOR: '1',
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    report: existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '',
  };
}

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
}, 180_000);

afterAll(() => {
  rmSync(resolve(demoDir, '.dephawk'), { recursive: true, force: true });
});

describe('e2e: demo under --import', () => {
  it('observes and attributes SSH read, NPM_TOKEN read and outbound connect', () => {
    const { stderr, report } = runDemo('observe');

    // Console report
    expect(stderr).toContain('dephawk report');
    expect(stderr).toContain('sneaky-dependency');
    expect(stderr).toContain('.ssh');
    expect(stderr).toContain('NPM_TOKEN');
    expect(stderr).toContain('collector.dephawk-demo.invalid');

    // Shareable HTML artifact, attributed to the culprit package
    expect(report).toContain('<!doctype html>');
    expect(report).toContain('sneaky-dependency');
    expect(report).toContain('NPM_TOKEN');
    expect(report).toContain('.ssh');
  }, 60_000);

  it('blocks those same calls in enforce mode', () => {
    const { stderr, report } = runDemo('enforce');

    expect(stderr).toContain('sneaky-dependency');
    expect(stderr).toContain('[blocked]');
    expect(stderr).toContain('blocked by policy');

    // All three sensitive calls are attributed and blocked in the HTML report
    expect(report).toContain('sneaky-dependency');
    expect(report).toContain('blocked');
    expect(report).toContain('NPM_TOKEN');
    expect(report).toContain('.ssh');
    expect(report).toContain('collector.dephawk-demo.invalid');
  }, 60_000);
});
