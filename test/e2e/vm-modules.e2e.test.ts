import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// `vm.SourceTextModule` (behind --experimental-vm-modules) compiles and runs a
// source string outside the `vm.Script` surface, so a dependency with
// `eval: false` could execute compiled code through it. It must be gated as
// code.eval like every other vm entry.
const projectDir = join(tmpdir(), `dephawk-vm-modules-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const vm = require('node:vm');",
      'exports.run = async () => {',
      "  const m = new vm.SourceTextModule('globalThis.__vmEvil = 41 + 1;');",
      "  await m.link(() => { throw new Error('no imports'); });",
      '  await m.evaluate();',
      '  return globalThis.__vmEvil;',
      '};',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      "require('evil')",
      '  .run()',
      "  .then((v) => console.log('VM_MODULE_RAN=' + v))",
      "  .catch((e) => console.log('BLOCKED=' + /dephawk: blocked/.test(e.message)));",
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'dephawk.config.js'),
    "module.exports={mode:'enforce',default:{eval:false,env:false,spawn:false},packages:{}};",
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: vm.SourceTextModule is gated as code.eval', () => {
  it('blocks a dependency running compiled module code under eval:false', () => {
    const result = spawnSync(
      process.execPath,
      [
        '--experimental-vm-modules',
        cliPath,
        'run',
        '--config',
        join(projectDir, 'dephawk.config.js'),
        '--',
        'node',
        '--experimental-vm-modules',
        'app.js',
      ],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
      },
    );

    const out = result.stdout + result.stderr;
    expect(out).toContain('BLOCKED=true');
    expect(out).not.toContain('VM_MODULE_RAN');
    expect(out).toContain('vm.SourceTextModule');
  }, 60_000);
});
