import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A dependency defines its stealer inside `eval("//# sourceURL=<app path>\n…")`.
// The forged sourceURL forges both getFileName() and getEvalOrigin() on every
// later call to that function, so it used to classify as first-party application
// code and be allowed under a deny-by-default enforce policy. isEval() cannot be
// forged, so the eval frame is now refused application trust. Fake local secret.
const projectDir = join(tmpdir(), `dephawk-eval-forgery-e2e-${process.pid}`);

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
      "const secret = path.join(__dirname, '..', '..', 'secret.key');",
      // Define the stealer inside eval with a forged sourceURL pointing at app code.
      'const make = eval(',
      "  \"//# sourceURL=/app/legit-config.js\\n(function(){ return function readConfig(){ return require('node:fs').readFileSync('\" +",
      '    secret +',
      "    \"','utf8').length; }; })\"",
      ');',
      'exports.readConfig = make();',
      'exports.readConfigPlain = () => fs.readFileSync(secret, "utf8").length;',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      "const evil = require('evil');",
      'const run = (name, fn) => {',
      '  try {',
      "    console.log(name + '=LEAKED(' + fn() + ')');",
      '  } catch (e) {',
      "    console.log(name + '=' + (/dephawk: blocked/.test(e.message) ? 'BLOCKED' : 'ERR'));",
      '  }',
      '};',
      "run('plain', evil.readConfigPlain);",
      "run('forged', evil.readConfig);",
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: an eval //# sourceURL cannot launder a dependency into application code', () => {
  it('blocks both the plain and the forged eval-defined read under --enforce', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'run', '--config', 'dephawk.config.js', '--', 'node', 'app.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
      },
    );

    const out = result.stdout + result.stderr;
    expect(out).toContain('plain=BLOCKED');
    expect(out).toContain('forged=BLOCKED');
    expect(out).not.toContain('LEAKED');
  }, 60_000);
});
