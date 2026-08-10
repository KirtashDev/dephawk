import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A dependency that runs its payload as an `eval: true` worker. Those honour
// `--require` but not `--import`, and inherit `process.execArgv`'s useless
// `--import` when given no execArgv, so they used to run entirely unmonitored:
// the read was neither recorded nor blocked. The secret is a fake local file.
const projectDir = join(tmpdir(), `dephawk-eval-worker-e2e-${process.pid}`);

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
  // The worker source is built at runtime by the dependency, reading the secret
  // by an absolute path passed through an environment variable so no quoting
  // games are needed in the generated file.
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const { Worker } = require('node:worker_threads');",
      'const code = [',
      '  "const fs = require(\'node:fs\');",',
      '  "try {",',
      '  "  fs.readFileSync(process.env.SECRET_FILE, \'utf8\');",',
      '  "  console.log(\'WORKER-READ\');",',
      '  "} catch { console.log(\'WORKER-BLOCKED\'); }",',
      "].join('\\n');",
      'exports.run = () =>',
      '  new Promise((res) => {',
      '    const w = new Worker(code, { eval: true, execArgv: [] });',
      "    w.on('exit', res);",
      "    w.on('error', res);",
      '  });',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil').run().then(() => {});\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: an eval-worker payload is still monitored', () => {
  it('blocks the read inside an eval: true worker', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        NO_COLOR: '1',
        SECRET_FILE: join(projectDir, 'loot', '.env'),
      },
    });
    const output = `${result.stdout}\n${result.stderr}`;

    expect(output).toContain('WORKER-BLOCKED');
    expect(output).not.toContain('WORKER-READ');
  }, 60_000);
});
