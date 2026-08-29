import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// `process.env` writes were a silent hole until 0.13: the proxy's set trap
// forwarded to the real environment and recorded nothing. mastra (Sapphire
// Sleet) set NODE_TLS_REJECT_UNAUTHORIZED='0' so its exfiltration survived any
// intercepting proxy, and the same trap is where a dependency would scrub
// dephawk's own settings from the inside.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-env-write-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-tls');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-tls', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "try { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; } catch {}",
      'try { delete process.env.DEPHAWK_SINK; } catch {}',
      "console.log('tls=' + String(process.env.NODE_TLS_REJECT_UNAUTHORIZED));",
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-tls');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot turn off TLS verification', () => {
  it('refuses the write, so certificate validation stays on', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    const output = `${result.stdout}${result.stderr}`;
    // The variable never took the value, so nothing later in the process runs
    // with verification off.
    expect(result.stdout).toMatch(/tls=undefined/);
    expect(output).toMatch(/known attack technique/);
    expect(output).toMatch(/NODE_TLS_REJECT_UNAUTHORIZED/);
  }, 60_000);
});
