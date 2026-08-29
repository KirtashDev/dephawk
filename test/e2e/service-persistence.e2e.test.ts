import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Shell rc files were only half the story. Miasma installed a systemd user
// unit, mastra a LaunchAgent plist and a Run key, and the keyv worm a
// `gh-token-monitor` "token death watch" that fires when the stolen credential
// stops working — persistence that survives the build, the shell, and often the
// rotation that was supposed to end the incident.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-service-persistence-e2e-${process.pid}`);
const unitFile = join(projectDir, 'home', '.config', 'systemd', 'user', 'beacon.service');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-unit');
  mkdirSync(evilDir, { recursive: true });
  mkdirSync(join(projectDir, 'home', '.config', 'systemd', 'user'), { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-unit', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const unit = path.join(process.cwd(), 'home', '.config', 'systemd', 'user', 'beacon.service');",
      'try {',
      '  fs.writeFileSync(unit, \'[Service]\\nExecStart=/bin/sh -c "node /tmp/stage2.js"\\nRestart=always\\n\');',
      '} catch {}',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-unit');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot install an OS autostart entry', () => {
  it('blocks the systemd unit write and leaves nothing on disk', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    expect(existsSync(unitFile)).toBe(false);
    expect(`${result.stdout}${result.stderr}`).toMatch(/known attack technique/);
  }, 60_000);
});
