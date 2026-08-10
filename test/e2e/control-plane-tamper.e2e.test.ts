import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A dependency that attacks dephawk itself rather than a capability: it reads a
// secret and then tries to stop dephawk reporting it, or to run a child out of
// enforce. The key is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-tamper-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil');
  mkdirSync(evilDir, { recursive: true });
  mkdirSync(join(projectDir, 'loot'), { recursive: true });
  writeFileSync(join(projectDir, 'loot', '.env'), 'SECRET=fake\n');
  writeFileSync(
    join(projectDir, 'dephawk.config.js'),
    'export default { mode: "enforce", default: { fs: { read: [] } }, packages: { evil: { spawn: true } } };\n',
  );
  writeFileSync(
    join(evilDir, 'package.json'),
    '{ "name": "evil", "version": "1.0.0", "main": "index.js" }\n',
  );
  // The grandchild an env-downgrade attack would run.
  writeFileSync(
    join(evilDir, 'child.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'try {',
      "  fs.readFileSync(path.join(__dirname, '..', '..', 'loot', '.env'), 'utf8');",
      "  console.log('CHILD-READ-OK');",
      "} catch { console.log('CHILD-BLOCKED'); }",
    ].join('\n'),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const secret = path.join(__dirname, '..', '..', 'loot', '.env');",
      'exports.silence = () => {',
      "  try { fs.readFileSync(secret, 'utf8'); } catch {}",
      "  process.removeAllListeners('exit');",
      "  process.removeAllListeners('beforeExit');",
      '};',
      'exports.downgradeChild = () => {',
      "  const { execFileSync } = require('node:child_process');",
      '  const env = Object.create(null);',
      "  env.PATH = '/usr/bin:/bin';",
      "  env.DEPHAWK_MODE = 'observe';",
      "  const out = execFileSync(process.execPath, [path.join(__dirname, 'child.js')],",
      "    { encoding: 'utf8', env });",
      '  process.stdout.write(out);',
      '};',
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function run(entry: string): { code: number | null; output: string } {
  writeFileSync(join(projectDir, 'app.js'), `require('evil').${entry}();\n`);
  const result = spawnSync(
    process.execPath,
    [
      cliPath,
      'run',
      '--config',
      'dephawk.config.js',
      '--fail-on',
      'violation',
      'node',
      'app.js',
    ],
    { cwd: projectDir, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
  );
  return { code: result.status, output: `${result.stdout}\n${result.stderr}` };
}

describe('e2e: a dependency cannot tamper with dephawk itself', () => {
  it('still reports and fails the gate when the exit listeners are removed', () => {
    // The record is streamed to the shared sink as each call happens, so
    // dropping the exit handler cannot erase what already occurred.
    const { code, output } = run('silence');
    expect(output).toContain('evil');
    expect(output).toContain('read');
    expect(output).not.toContain('no monitored activity recorded');
    expect(code).toBe(2);
  }, 60_000);

  it('does not let a spawned child be downgraded out of enforce', () => {
    // The child is spawned with DEPHAWK_MODE=observe injected. The pinned policy
    // is authoritative, so the read is blocked rather than run.
    const { output } = run('downgradeChild');
    expect(output).toContain('CHILD-BLOCKED');
    expect(output).not.toContain('CHILD-READ-OK');
  }, 60_000);
});
