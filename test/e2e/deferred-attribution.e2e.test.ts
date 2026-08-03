import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A throwaway project whose dependency never calls a sensitive built-in
// directly: it hands the built-in itself to a scheduler, so that by the time
// the read happens its own frames are gone from the stack. Before dephawk 0.3
// that call was credited to "(your code)" and allowed even under --enforce.
// The key is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-deferred-e2e-${process.pid}`);
const reportPath = join(projectDir, '.dephawk', 'report.html');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  const laundererDir = join(projectDir, 'node_modules', 'launderer');
  mkdirSync(laundererDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-private-key\n');
  writeFileSync(
    join(laundererDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const key = path.join(__dirname, '..', '..', 'id_rsa');",
      '',
      '// Never calls readFileSync — only *schedules* it.',
      'exports.viaTimer = () => setTimeout(fs.readFileSync, 0, key);',
      'exports.viaPromise = () => Promise.resolve(key).then(fs.readFileSync);',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      "const { viaTimer, viaPromise } = require('launderer');",
      '',
      '// In enforce mode the blocked call throws from inside a timer, where no',
      '// try/catch can reach it. Swallow it so the process exits cleanly and',
      '// dephawk still gets to write its report.',
      "process.on('uncaughtException', () => {});",
      "process.on('unhandledRejection', () => {});",
      '',
      'viaTimer();',
      'viaPromise();',
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function runApp(mode: 'observe' | 'enforce'): { stderr: string; report: string } {
  const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'app.js'], {
    cwd: projectDir,
    encoding: 'utf8',
    env: { ...process.env, DEPHAWK_MODE: mode, NO_COLOR: '1' },
  });
  return {
    stderr: result.stderr,
    report: existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '',
  };
}

describe('e2e: calls laundered through an async boundary', () => {
  it('attributes a deferred, detached read back to the dependency', () => {
    const { stderr, report } = runApp('observe');

    expect(stderr).toContain('launderer');
    expect(stderr).not.toContain('(your code)');
    expect(report).toContain('launderer');
  }, 60_000);

  it('blocks it in enforce mode instead of trusting it as app code', () => {
    const { stderr } = runApp('enforce');

    expect(stderr).toContain('launderer');
    expect(stderr).toContain('[blocked]');
    expect(stderr).not.toContain('(your code)');
  }, 60_000);
});
