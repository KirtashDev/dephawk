import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A dependency that does its dirty work in a grandchild it starts with dephawk
// scrubbed out of the environment. Monitoring spreads by inheritance, so before
// this was fixed the spawn was recorded and everything after it was invisible.
// The key is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-envstrip-e2e-${process.pid}`);
const reportPath = join(projectDir, '.dephawk', 'report.html');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  const sneakyDir = join(projectDir, 'node_modules', 'sneaky');
  mkdirSync(sneakyDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-private-key\n');

  writeFileSync(
    join(sneakyDir, 'payload.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8');",
    ].join('\n'),
  );

  writeFileSync(
    join(sneakyDir, 'index.js'),
    [
      "const { spawnSync } = require('node:child_process');",
      "const path = require('node:path');",
      'exports.viaScrubbedEnv = () => {',
      '  const clean = { ...process.env };',
      '  delete clean.NODE_OPTIONS;',
      '  delete clean.DEPHAWK_POLICY;',
      '  delete clean.DEPHAWK_SINK;',
      '  spawnSync(',
      '    process.execPath,',
      "    [path.join(__dirname, 'payload.js')],",
      "    { stdio: 'inherit', env: clean },",
      '  );',
      '};',
      'exports.viaDeletedProcessEnv = () => {',
      '  // No explicit env: poison the inherited one instead.',
      '  delete process.env.NODE_OPTIONS;',
      '  delete process.env.DEPHAWK_POLICY;',
      '  delete process.env.DEPHAWK_SINK;',
      '  spawnSync(',
      '    process.execPath,',
      "    [path.join(__dirname, 'payload.js')],",
      "    { stdio: 'inherit' },",
      '  );',
      '};',
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function guard(entry: string): { stderr: string; report: string } {
  writeFileSync(join(projectDir, 'app.js'), `require('sneaky').${entry}();\n`);
  const result = spawnSync(process.execPath, [cliPath, 'guard', 'node', 'app.js'], {
    cwd: projectDir,
    encoding: 'utf8',
    env: { ...process.env, DEPHAWK_MODE: 'observe', NO_COLOR: '1' },
  });
  return {
    stderr: result.stderr,
    report: existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '',
  };
}

describe('e2e: a dependency cannot spawn its way out of monitoring', () => {
  it('re-attaches when the child is given a scrubbed environment', () => {
    const { stderr, report } = guard('viaScrubbedEnv');

    // The grandchild's read lands in the aggregated report, attributed.
    expect(stderr).toContain('sneaky');
    expect(report).toContain('id_rsa');
    // And the report says what had to be put back.
    expect(report).toContain('re-attached');
    expect(report).toContain('NODE_OPTIONS');
  }, 60_000);

  it('re-attaches when the variables were deleted from process.env instead', () => {
    const { report } = guard('viaDeletedProcessEnv');

    expect(report).toContain('id_rsa');
    expect(report).toContain('re-attached');
  }, 60_000);
});
