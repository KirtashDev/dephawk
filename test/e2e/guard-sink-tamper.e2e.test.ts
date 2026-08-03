import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// Two lifecycle scripts, run in order: one reads an SSH key, then one wipes the
// shared sink whose location it learns from DEPHAWK_SINK. Before this was
// fixed, the wipe erased the first script's evidence and the aggregated report
// came back clean. The key is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-tamper-e2e-${process.pid}`);
const reportPath = join(projectDir, '.dephawk', 'report.html');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  const victimDir = join(projectDir, 'node_modules', 'victim');
  const wiperDir = join(projectDir, 'node_modules', 'wiper');
  mkdirSync(victimDir, { recursive: true });
  mkdirSync(wiperDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-private-key\n');

  writeFileSync(
    join(victimDir, 'postinstall.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8');",
    ].join('\n'),
  );

  writeFileSync(
    join(wiperDir, 'postinstall.js'),
    [
      "const fs = require('node:fs');",
      'const sink = process.env.DEPHAWK_SINK;',
      '// Left uncaught on purpose: a blocked call crashes the script, and the',
      "// guard's `exit` flush must still record what it tried to do.",
      'fs.truncateSync(sink, 0);',
    ].join('\n'),
  );

  writeFileSync(
    join(projectDir, 'installer.js'),
    [
      "const { spawnSync } = require('node:child_process');",
      "const path = require('node:path');",
      'const run = (pkg) =>',
      '  spawnSync(',
      '    process.execPath,',
      "    [path.join(__dirname, 'node_modules', pkg, 'postinstall.js')],",
      "    { stdio: 'inherit' },",
      '  );',
      "run('victim');",
      "run('wiper');",
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function guard(mode: 'observe' | 'enforce'): { stderr: string; report: string } {
  const result = spawnSync(process.execPath, [cliPath, 'guard', 'node', 'installer.js'], {
    cwd: projectDir,
    encoding: 'utf8',
    env: { ...process.env, DEPHAWK_MODE: mode, NO_COLOR: '1' },
  });
  return {
    stderr: result.stderr,
    report: existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '',
  };
}

describe('e2e: a lifecycle script cannot erase the guard audit log', () => {
  it('keeps the earlier evidence and reports the tampering — in observe mode', () => {
    // Observe mode blocks nothing *of the program's own doing*, but the sink is
    // dephawk's, and recording an attempt on the record itself is worthless.
    const { stderr, report } = guard('observe');

    // The console truncates long temp paths, so the package and capability are
    // asserted here and the full path in the untruncated HTML.
    expect(stderr).toContain('victim');
    expect(stderr).toContain('read');
    expect(report).toContain('id_rsa');

    expect(stderr).toContain('wiper');
    expect(stderr).toContain('[blocked]');
    // The refusal names the sink and says why, on the way out of the script.
    expect(stderr).toContain('audit log');
    expect(report).toContain('events.jsonl');
  }, 60_000);

  it('does the same under enforce', () => {
    const { stderr, report } = guard('enforce');

    expect(stderr).toContain('victim');
    expect(report).toContain('id_rsa');
    expect(stderr).toContain('wiper');
    expect(stderr).toContain('[blocked]');
  }, 60_000);

  it('leaves no sink directory behind in the temp directory', () => {
    // Compare before and after rather than asserting the temp directory holds
    // no `dephawk-guard-*` at all: the other e2e suites keep their own fixtures
    // there under names sharing that prefix, and vitest runs files in parallel.
    // What this test means is "this run cleaned up after itself".
    const sinkDirs = (): string[] =>
      readdirSync(tmpdir()).filter((name) => name.startsWith('dephawk-guard-'));
    const before = new Set(sinkDirs());

    guard('observe');

    expect(sinkDirs().filter((name) => !before.has(name))).toEqual([]);
  }, 60_000);
});
