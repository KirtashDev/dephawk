import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A project with one dependency that legitimately reads a config file and one
// that shells out. Both are things a real project has, and both would need
// hand-written rules before `--enforce` could ever go green.
const projectDir = join(tmpdir(), `dephawk-init-e2e-${process.pid}`);
const configPath = join(projectDir, 'dephawk.config.js');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  mkdirSync(join(projectDir, 'node_modules', 'reader'), { recursive: true });
  mkdirSync(join(projectDir, 'node_modules', 'builder'), { recursive: true });
  mkdirSync(join(projectDir, 'node_modules', 'snoop'), { recursive: true });
  writeFileSync(join(projectDir, '.npmrc'), 'registry=https://registry.npmjs.org/\n');
  writeFileSync(join(projectDir, 'id_rsa'), 'not-a-real-key\n');

  writeFileSync(
    join(projectDir, 'node_modules', 'reader', 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "exports.go = () => fs.readFileSync(path.join(__dirname, '..', '..', '.npmrc'), 'utf8');",
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'node_modules', 'builder', 'index.js'),
    [
      "const { execFileSync } = require('node:child_process');",
      "exports.go = () => execFileSync(process.execPath, ['-e', '1']);",
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    ["require('reader').go();", "require('builder').go();"].join('\n'),
  );
  // A package the drafted policy never saw, doing something it never granted.
  // It has to be a *dependency* reading a *sensitive* name: application code is
  // always allowed, and only certain filenames count as secret-bearing.
  writeFileSync(
    join(projectDir, 'node_modules', 'snoop', 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "exports.go = () => fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8');",
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app-extra.js'),
    ["require('reader').go();", "require('snoop').go();"].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function dephawk(...args: string[]): { status: number | null; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: projectDir,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: result.status, stderr: result.stderr };
}

describe('e2e: init drafts a policy you can actually enforce', () => {
  it('writes a config granting what the run did, and says what to review', () => {
    const result = dephawk('init', 'node', 'app.js');

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('policy drafted at');
    expect(result.stderr).toContain('builder: process.spawn');
    expect(result.stderr).toContain('Read it before you trust it');

    const config = readFileSync(configPath, 'utf8');
    expect(config).toContain('because it HAPPENED');
    expect(config).toContain('reader:');
    expect(config).toContain('builder:');
    expect(config).toContain('spawn: true');
    // The default bucket stays shut, or the draft would grant everything.
    expect(config).toContain('spawn: false');
  }, 60_000);

  it('refuses to clobber an existing policy without --force', () => {
    const before = readFileSync(configPath, 'utf8');
    const result = dephawk('init', 'node', 'app.js');

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('already exists');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  }, 60_000);

  it('overwrites with --force', () => {
    expect(dephawk('init', '--force', 'node', 'app.js').status).toBe(0);
  }, 60_000);

  it('the drafted policy makes the same run pass under --enforce', () => {
    // The whole point: from "wall of denials" to green, without hand-writing it.
    const result = dephawk(
      'run',
      '--enforce',
      '--fail-on',
      'violation',
      'node',
      'app.js',
    );

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain('[blocked]');
  }, 60_000);

  it('catches behaviour the draft never saw, and fails the run for it', () => {
    // Observe mode: nothing is blocked, so the exit code is purely the verdict.
    const result = dephawk('run', '--fail-on', 'violation', 'node', 'app-extra.js');

    expect(result.status).toBe(2);
    // The console truncates long temp paths, so assert on the culprit.
    expect(result.stderr).toContain('snoop');
    expect(result.stderr).toContain('policy violation');
  }, 60_000);

  it('blocks it under --enforce, and the crash is what fails the run', () => {
    const result = dephawk(
      'run',
      '--enforce',
      '--fail-on',
      'violation',
      'node',
      'app-extra.js',
    );

    // The blocked call throws inside the program, so the program's own failure
    // is what surfaces — `--fail-on`'s exit code never gets a look in. Either
    // way the run is red, and the report still lands: the child flushes its
    // events on `exit`, which runs even when it dies of an uncaught error.
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('blocked fs.read');
    expect(result.stderr).toContain('snoop');
  }, 60_000);

  it('writes to --out when asked', () => {
    const alt = join(projectDir, 'other.config.js');
    const result = dephawk('init', '--out', alt, 'node', 'app.js');

    expect(result.status).toBe(0);
    expect(existsSync(alt)).toBe(true);
  }, 60_000);
});
