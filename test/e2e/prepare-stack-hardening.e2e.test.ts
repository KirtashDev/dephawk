import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// Two ways a dependency tried to keep dephawk from installing its own
// Error.prepareStackTrace formatter during a capture:
//  1. redefine it as an accessor whose *setter swallows* the assignment, then
//     the getter forges an application frame → trusted for any capability;
//  2. leave callerLocation un-hardened and forge a `node:internal/deps/` caller
//     so the WASM interceptor treats the payload as Node's own plumbing.
// Both must fail closed. Fake local secret; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-prepstack-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    '{ "name": "evil", "version": "1.0.0", "main": "index.js" }\n',
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      'exports.accessorForger = () => {',
      "  Object.defineProperty(Error, 'prepareStackTrace', {",
      '    configurable: true,',
      "    get() { return () => 'Error\\n    at steal (/app/main.js:1:1)\\n'; },",
      '    set() {},', // swallow dephawk's install
      '  });',
      "  try { return 'read:' + fs.readFileSync('/etc/passwd', 'utf8').length; }",
      "  catch (e) { return /dephawk: blocked/.test(e.message) ? 'BLOCKED' : 'ERR'; }",
      '};',
      'exports.wasmDepsForger = async () => {',
      "  Error.prepareStackTrace = () => 'Error\\n    at x (node:internal/deps/undici/undici.js:1:1)\\n';",
      '  const bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);',
      "  try { await WebAssembly.instantiate(bytes); return 'RAN'; }",
      "  catch (e) { return /dephawk: blocked/.test(e.message) ? 'BLOCKED' : 'ERR'; }",
      '};',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'dephawk.config.js'),
    'export default { mode: "enforce", default: { fs: { read: [] }, eval: false }, packages: {} };\n',
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      "const evil = require('evil');",
      "evil.accessorForger && console.log('ACCESSOR=' + evil.accessorForger());",
      "evil.wasmDepsForger().then((r) => console.log('WASM=' + r));",
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot defeat the prepareStackTrace formatter install', () => {
  it('blocks an accessor-setter stack forger and a forged node:internal/deps wasm caller', () => {
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
    expect(out).toContain('ACCESSOR=BLOCKED'); // not trusted as application code
    expect(out).toContain('WASM=BLOCKED'); // not skipped as runtime plumbing
    expect(out).not.toContain('read:'); // the secret was never read
  }, 60_000);
});
