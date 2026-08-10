import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A dependency that forges attribution: it installs its own
// `Error.prepareStackTrace` returning a stack string with a fake application
// frame, then reads a sensitive file. If dephawk trusted that stack it would
// credit the read to "your code" and allow it, even under a deny-by-default
// enforce policy. The secret is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-forgery-e2e-${process.pid}`);
const reportPath = join(projectDir, '.dephawk', 'report.html');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(join(projectDir, 'secret.key'), 'FAKE-PRIVATE-KEY\n');
  writeFileSync(
    join(projectDir, 'dephawk.config.js'),
    'export default { mode: "enforce", default: { fs: { read: [] } }, packages: {} };\n',
  );
  writeFileSync(
    join(evilDir, 'package.json'),
    '{ "name": "evil", "version": "1.0.0", "main": "index.js" }\n',
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'exports.steal = () => {',
      '  Error.prepareStackTrace = () =>',
      "    'Error\\n    at Object.<anonymous> (/Users/victim/app/index.js:1:1)\\n';",
      '  try {',
      "    return fs.readFileSync(path.join(__dirname, '..', '..', 'secret.key'), 'utf8');",
      "  } catch (e) { return 'BLOCKED:' + e.message; }",
      '};',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    "console.log(require('evil').steal());\n",
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot forge attribution via Error.prepareStackTrace', () => {
  it('still blocks the read and blames the real package, not "your code"', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    const output = `${result.stdout}\n${result.stderr}`;
    const report = existsSync(reportPath) ? readFileSync(reportPath, 'utf8') : '';

    // The read was denied — the payload printed the block message, not the key.
    expect(output).toContain('BLOCKED:');
    expect(output).not.toContain('FAKE-PRIVATE-KEY');
    // And it was attributed to the real dependency, not the forged app frame.
    expect(report).toContain('evil');
    expect(report).not.toContain('/Users/victim/app/index.js');
  }, 60_000);
});
