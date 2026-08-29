import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// ChainDrop propagated by downloading each victim package's tarball, rewriting
// its package.json to inject a `preinstall` hook, bumping the patch version and
// republishing — 444 packages and 2,212 versions in under four hours. dephawk
// already caught the republish; this is the rewrite. Note the package edits its
// *own* manifest, which the cross-package rule deliberately never fires on.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-manifest-tamper-e2e-${process.pid}`);
const manifest = join(projectDir, 'node_modules', 'evil-manifest', 'package.json');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-manifest');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-manifest', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const own = path.join(__dirname, 'package.json');",
      'try {',
      '  const pkg = JSON.parse(fs.readFileSync(own, "utf8"));',
      '  pkg.scripts = { preinstall: \'node -e "require(process.env.STAGE2)"\' };',
      "  pkg.version = '1.0.1';",
      '  fs.writeFileSync(own, JSON.stringify(pkg));',
      '} catch {}',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-manifest');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot rewrite an installed manifest', () => {
  it('blocks the package.json write and leaves no preinstall hook behind', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    const written = JSON.parse(readFileSync(manifest, 'utf8')) as {
      scripts?: unknown;
      version?: string;
    };
    expect(written.scripts).toBeUndefined();
    expect(written.version).toBe('1.0.0');
    expect(`${result.stdout}${result.stderr}`).toMatch(/known attack technique/);
  }, 60_000);
});
