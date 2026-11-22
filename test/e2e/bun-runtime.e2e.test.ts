import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Bun runs on JavaScriptCore, which implements ES2015 proper tail calls: a
// function ending in `return f()` is *removed from the stack* — and Bun's
// transpiler turns `const s = f(); return s;` into exactly that. Attribution
// reads the stack, so a dependency whose function ends in
// `return fs.readFileSync(key)` simply was not on it. Under 0.14 every event on
// Bun read as unattributed (dephawk's own boundary frame was elided too); left
// half-fixed, the surviving frame would have been the *application* that called
// into the dependency — which `--enforce` trusts unconditionally.
//
// `dephawk run` now starts Bun with `BUN_OPTIONS=--preload` and
// `BUN_JSC_useTailCalls=false`; a bare `--preload` without the switch is told
// so, and judges every event as unknown origin rather than guessing.
const bun = spawnSync('bun', ['--version'], { encoding: 'utf8' });
const hasBun = bun.status === 0;

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-bun-e2e-${process.pid}`);
const secret = join(projectDir, 'home', '.ssh', 'id_rsa_dephawk_bun_e2e');

beforeAll(() => {
  if (!hasBun) {
    return;
  }
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'tail-thief');
  mkdirSync(evilDir, { recursive: true });
  mkdirSync(join(projectDir, 'home', '.ssh'), { recursive: true });
  writeFileSync(secret, 'not a real key');
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'tail-thief', version: '1.0.0', main: 'index.js' }),
  );
  // Both the read and the call into it are in tail position: the dependency's
  // frames are exactly the ones a tail-calling engine removes.
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "'use strict';",
      "const fs = require('node:fs');",
      'function steal(path) { return fs.readFileSync(path, "utf8"); }',
      'module.exports = function helper(path) { return steal(path); };',
    ].join('\n'),
  );
  // Bun's native API, which never touches a Node built-in.
  const nativeDir = join(projectDir, 'node_modules', 'bun-native-thief');
  mkdirSync(nativeDir, { recursive: true });
  writeFileSync(
    join(nativeDir, 'package.json'),
    JSON.stringify({ name: 'bun-native-thief', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(nativeDir, 'index.js'),
    [
      'module.exports = async (key) => {',
      '  const out = [];',
      "  try { await Bun.file(key).text(); out.push('file:READ'); } catch { out.push('file:BLOCKED'); }",
      "  try { await Bun.write('CLAUDE.md', 'obey'); out.push('write:DONE'); } catch { out.push('write:BLOCKED'); }",
      "  try { Bun.spawnSync(['true'], { env: {} }); out.push('spawn:RAN'); } catch { out.push('spawn:BLOCKED'); }",
      "  try { await Bun.$`true`.quiet(); out.push('shell:RAN'); } catch { out.push('shell:BLOCKED'); }",
      "  try { Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: () => new Response('') }).stop(true); out.push('serve:BOUND'); } catch { out.push('serve:BLOCKED'); }",
      "  return out.join(' ');",
      '};',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'native.js'),
    `require('bun-native-thief')(${JSON.stringify(secret)}).then((r) => console.log(r));\n`,
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      "const helper = require('tail-thief');",
      `try { helper(${JSON.stringify(secret)}); console.log('READ'); } catch { console.log('BLOCKED'); }`,
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe.skipIf(!hasBun)('e2e: Bun', () => {
  it('dephawk run attributes a tail-calling dependency and blocks it under enforce', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'run', '--enforce', '--', 'bun', 'app.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1', COLUMNS: '200' },
      },
    );
    const out = `${result.stdout}${result.stderr}`;
    expect(out).toContain('BLOCKED');
    expect(out).not.toContain('READ');
    expect(out).toMatch(/tail-thief\s+→\s+read/);
    expect(out).not.toMatch(/unattributed/);
  }, 60_000);

  it('a bare --preload with tail calls on warns and never trusts a surviving frame', () => {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      NO_COLOR: '1',
      DEPHAWK_MODE: 'enforce',
    };
    delete env['BUN_JSC_useTailCalls'];
    delete env['BUN_OPTIONS'];
    const result = spawnSync('bun', ['--preload', registerPath, 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env,
    });
    const out = `${result.stdout}${result.stderr}`;
    expect(out).toMatch(/drops stack frames on tail calls/);
    // Unknown origin is deny-by-default: the read does not go through as the
    // application's.
    expect(out).toContain('BLOCKED');
  }, 60_000);

  it('watches Bun’s native API: Bun.file, Bun.write, Bun.spawn, Bun.$, Bun.serve', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'run', '--enforce', '--', 'bun', 'native.js'],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1', COLUMNS: '200' },
      },
    );
    const out = `${result.stdout}${result.stderr}`;
    expect(out).toContain(
      'file:BLOCKED write:BLOCKED spawn:BLOCKED shell:BLOCKED serve:BLOCKED',
    );
    expect(existsSync(join(projectDir, 'CLAUDE.md'))).toBe(false);
    expect(out).toMatch(/bun-native-thief\s+→\s+read/);
    expect(out).not.toMatch(/unattributed/);
  }, 60_000);
});
