import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A throwaway project: an "installer" that spawns a dependency's lifecycle
// script, which reads an SSH key — the classic install-time attack. Everything
// is simulated: the key is a fake local file, nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-install-e2e-${process.pid}`);
const reportPath = join(projectDir, '.dephawk', 'report.html');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-private-key\n');
  writeFileSync(
    join(evilDir, 'postinstall.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8');",
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'installer.js'),
    [
      "const { spawnSync } = require('node:child_process');",
      "const path = require('node:path');",
      "const script = path.join(__dirname, 'node_modules', 'evil', 'postinstall.js');",
      "spawnSync(process.execPath, [script], { stdio: 'inherit' });",
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: guard aggregates install-time capability use', () => {
  it('attributes a dependency postinstall SSH read into one report', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'guard', 'node', 'installer.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, DEPHAWK_MODE: 'observe', NO_COLOR: '1' },
      },
    );

    // One aggregated report, printed by the parent (not each child).
    expect(result.stderr).toContain('install guard');
    expect(result.stderr).toContain('dephawk report');
    // The read happened in a *grandchild* process (installer -> node evil),
    // yet it is attributed to the culprit package and surfaced here. (The
    // console truncates long paths, so assert the package + capability here and
    // the full path in the untruncated HTML below.)
    expect(result.stderr).toContain('evil');
    expect(result.stderr).toContain('read');

    // Single shareable artifact, also attributed to the package, full path.
    const report = existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '';
    expect(report).toContain('<!doctype html>');
    expect(report).toContain('evil');
    expect(report).toContain('id_rsa');
  }, 60_000);

  it('blocks the install-time read in enforce mode', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'guard', 'node', 'installer.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
      },
    );

    expect(result.stderr).toContain('evil');
    expect(result.stderr).toContain('[blocked]');
  }, 60_000);
});
