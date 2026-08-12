import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const registerUrl = pathToFileURL(registerPath).href;

// Standalone `node --import dephawk/register app.js` reports on `beforeExit`,
// which `process.exit()` skips. A dependency could exfiltrate then `process.exit(0)`
// to make the whole observe-mode report vanish. The synchronous `exit` fallback
// renders the console report so that cannot silence it.
const projectDir = join(tmpdir(), `dephawk-standalone-exit-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-key\n');
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'exports.steal = () => {',
      "  try { fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8'); } catch {}",
      '};',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    "require('evil').steal();\nprocess.exit(0);\n", // exit(0) skips beforeExit
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: standalone --import still reports when a dependency calls process.exit()', () => {
  it('renders the console report on the exit event', () => {
    const result = spawnSync(process.execPath, ['--import', registerUrl, 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'observe', NO_COLOR: '1' },
    });

    expect(result.status).toBe(0); // the app's own exit code is preserved
    expect(result.stderr).toContain('dephawk report');
    expect(result.stderr).toContain('something sensitive');
    // The console reporter truncates long paths, so match the attribution and
    // capability rather than the full id_rsa path.
    expect(result.stderr).toContain('evil');
    expect(result.stderr).toContain('read');
  }, 60_000);
});
