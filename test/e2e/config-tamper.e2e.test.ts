import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// The config file is a protected path: a dependency that could rewrite it would
// grant itself anything on the next run. The tamper check is by path, and on a
// symlinked location (macOS `$TMPDIR` -> `/private/var/…`) the config's resolved
// path and its canonical path differ, so a dependency could rewrite the same
// file through its canonical name. Both spellings must be refused.
const projectDir = join(tmpdir(), `dephawk-config-tamper-e2e-${process.pid}`);
const configPath = join(projectDir, 'dephawk.config.js');
const ORIGINAL =
  "module.exports={mode:'enforce',default:{fs:{read:[],write:[]},env:false,spawn:false},packages:{}};";

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(configPath, `${ORIGINAL}\n`);
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      'exports.tamper = () => {',
      '  const cfg = process.env.DEPHAWK_CONFIG;',
      '  const pwned = "module.exports={mode:\'observe\',default:{},packages:{}};// PWNED";',
      '  // Direct path, and the canonical (symlink-resolved) alias.',
      '  try { fs.writeFileSync(cfg, pwned); } catch {}',
      '  try { fs.writeFileSync(fs.realpathSync(cfg), pwned); } catch {}',
      '};',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil').tamper();\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot overwrite the config, even via a canonical alias', () => {
  it('leaves the config unchanged and blocks both spellings', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'run', '--config', configPath, '--', 'node', 'app.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
      },
    );

    // The config on disk is untouched — the allow-all payload never landed.
    const onDisk = readFileSync(configPath, 'utf8');
    expect(onDisk).toContain('enforce');
    expect(onDisk).not.toContain('PWNED');
    // And dephawk refused the write rather than silently allowing it.
    expect(result.stderr).toMatch(/blocked|dephawk\.config\.js/);
  }, 60_000);
});

// Planting is the harder case: on a run with NO config the config's absolute path
// is unknown (DEPHAWK_CONFIG unset), so it cannot be a protected path — yet a
// dependency dropping `dephawk.config.js` in the cwd would have the NEXT run load
// it as policy. The basename check must refuse the write anyway.
describe('e2e: a dependency cannot PLANT a config on a no-config run', () => {
  const plantDir = join(tmpdir(), `dephawk-config-plant-e2e-${process.pid}`);
  const plantedConfig = join(plantDir, 'dephawk.config.js');

  beforeAll(() => {
    const evilDir = join(plantDir, 'node_modules', 'evil-plant');
    mkdirSync(evilDir, { recursive: true });
    writeFileSync(
      join(evilDir, 'package.json'),
      JSON.stringify({ name: 'evil-plant', version: '1.0.0', main: 'index.js' }),
    );
    writeFileSync(
      join(evilDir, 'index.js'),
      [
        "const fs = require('node:fs');",
        "const path = require('node:path');",
        'const pwned =',
        '  "export default { default: { net: { connect: [\'*\'] }, spawn: true, env: true } };";',
        '  try { fs.writeFileSync(path.join(process.cwd(), "dephawk.config.js"), pwned); } catch {}',
      ].join('\n'),
    );
    writeFileSync(join(plantDir, 'app.js'), "require('evil-plant');\n");
  }, 180_000);

  afterAll(() => rmSync(plantDir, { recursive: true, force: true }));

  it('blocks the write and leaves no config on disk', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: plantDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    expect(existsSync(plantedConfig)).toBe(false);
    expect(`${result.stdout}${result.stderr}`).toMatch(/blocked|dephawk\.config\.js/);
  }, 60_000);
});
