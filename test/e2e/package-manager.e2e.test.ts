import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// Everything else in this suite runs dephawk against a `node` script we wrote.
// That is precisely why nobody noticed that **npm did not run at all** under
// dephawk for every release up to 0.6.5: assigning `process.env.HOME` through
// the env Proxy threw
// `TypeError: 'process.env' only accepts a configurable, writable, and
// enumerable data descriptor`, npm's config load rejected, and npm exited 1 in
// silence — no install, no message, not even its own debug log.
//
// So this file runs the real package manager. `--version` is enough: it fails
// on exactly the same config-loading path as `install`, and needs no network.
beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
}, 180_000);

describe('e2e: a real package manager still runs under dephawk', () => {
  it('lets npm start, print its version and exit cleanly', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', 'npm', '--version'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });

    const output = `${result.stdout}\n${result.stderr}`;
    // npm printed a version, rather than dying silently.
    expect(output).toMatch(/^\d+\.\d+\.\d+$/m);
    expect(result.status).toBe(0);
  }, 120_000);

  it('lets a program overwrite an inherited env var, as npm does with HOME', () => {
    // The narrow mechanism behind the above: *overwriting* an existing variable
    // is what threw, and the value must still reach the real environment so a
    // child inherits it.
    const script = [
      "process.env.DEPHAWK_E2E_PROBE = 'first';",
      "process.env.DEPHAWK_E2E_PROBE = 'set-through-the-proxy';",
      'const { execFileSync } = require("node:child_process");',
      'const seen = execFileSync(process.execPath,',
      '  ["-p", "process.env.DEPHAWK_E2E_PROBE"], { encoding: "utf8" }).trim();',
      'console.log("CHILD_SAW:" + seen);',
    ].join('\n');

    const result = spawnSync(process.execPath, [cliPath, 'run', 'node', '-e', script], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });

    expect(`${result.stdout}\n${result.stderr}`).toContain(
      'CHILD_SAW:set-through-the-proxy',
    );
  }, 120_000);
});
