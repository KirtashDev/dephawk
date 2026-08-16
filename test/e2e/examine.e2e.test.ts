import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// `dephawk x <package>` installs a package in a throwaway sandbox, runs it, and
// reports what it actually did. Exercised against a LOCAL package (copied in via
// --install-links, so it is attributed like any dependency) — no registry needed
// for the package itself.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const pkgDir = join(tmpdir(), `dephawk-examine-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(
    join(pkgDir, 'package.json'),
    JSON.stringify({ name: 'totally-safe-utils', version: '1.0.0', main: 'index.js' }),
  );
  // Reads a cloud-credential path and reaches a dead-drop host on import.
  writeFileSync(
    join(pkgDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const os = require('node:os');",
      "try { fs.readFileSync(os.homedir() + '/.aws/credentials'); } catch {}",
      "try { require('node:dns').resolve('api.telegram.org', () => {}); } catch {}",
    ].join('\n'),
  );
}, 180_000);

afterAll(() => rmSync(pkgDir, { recursive: true, force: true }));

describe('e2e: dephawk x reports what a package does', () => {
  it('flags a package that reads a secret and reaches a dead-drop host', () => {
    const result = spawnSync(process.execPath, [cliPath, 'x', pkgDir, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });

    const report = JSON.parse(result.stdout) as {
      package: string;
      recognisedTechniques: string[];
      likelyCredentialExfiltration: { package: string }[];
      findings: { detail: string }[];
    };
    expect(report.package).toBe('totally-safe-utils');
    expect(report.recognisedTechniques).toContain('dead-drop-c2');
    expect(report.likelyCredentialExfiltration.length).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.detail.includes('credentials'))).toBe(true);
  }, 120_000);
});
