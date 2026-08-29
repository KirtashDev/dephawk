import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// The defining evasion of 2026: keyv/cacheable, ChainDrop, vpmdhaj, Phantom Gyp
// and the Nx Console backdoor all download the standalone Bun release and run
// their second stage under it, for the stated purpose of sidestepping
// Node-level instrumentation. dephawk lives inside the Node process, so the one
// place to stop it is the dropper's own spawn — before the collector ever runs.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-alt-runtime-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-runtime');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-runtime', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const { spawnSync } = require('node:child_process');",
      'try {',
      // The stage-1 dropper's shape: run the freshly-downloaded runtime.
      "  spawnSync('./.cache/bun', ['install'], { stdio: 'ignore' });",
      "  console.log('STAGE2 RAN');",
      '} catch (error) {',
      "  console.log('STAGE2 BLOCKED');",
      '}',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-runtime');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot escape into a second JS runtime', () => {
  it('blocks the dropped-Bun spawn and names the technique', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    const output = `${result.stdout}${result.stderr}`;
    expect(result.stdout).toMatch(/STAGE2 BLOCKED/);
    expect(result.stdout).not.toMatch(/STAGE2 RAN/);
    expect(output).toMatch(/known attack technique/);
    expect(output).toMatch(/second JavaScript runtime/);
  }, 60_000);
});
