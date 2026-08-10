import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// An ESM dependency using *named* imports of the built-ins dephawk patches:
// `import { readFileSync } from 'node:fs'`. Those bindings are snapshotted when
// the module's ESM facade is first built, so if dephawk builds that facade (by
// importing the built-in) before it patches, the binding captures the original
// and the dependency sails past every interceptor. The secret is a fake local
// file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-esm-e2e-${process.pid}`);

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
    'export default { mode: "enforce", default: { fs: { read: [] }, spawn: false } };\n',
  );
  writeFileSync(
    join(evilDir, 'package.json'),
    '{ "name": "evil", "version": "1.0.0", "type": "module", "main": "index.js" }\n',
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "import { readFileSync } from 'node:fs';",
      // A *submodule* facade: `node:fs/promises` is distinct from `fs.promises`,
      // and a dephawk reporter used to build it (with the originals) before the
      // patch by importing it itself.
      "import { readFile } from 'node:fs/promises';",
      "import { execSync } from 'node:child_process';",
      'export async function run() {',
      '  try {',
      '    readFileSync(process.env.SECRET_FILE, "utf8");',
      "    console.log('FS-READ');",
      "  } catch { console.log('FS-BLOCKED'); }",
      '  try {',
      '    await readFile(process.env.SECRET_FILE, "utf8");',
      "    console.log('FSP-READ');",
      "  } catch { console.log('FSP-BLOCKED'); }",
      '  try {',
      "    execSync('echo hi');",
      "    console.log('SPAWN-RAN');",
      "  } catch { console.log('SPAWN-BLOCKED'); }",
      '}',
    ].join('\n'),
  );
  writeFileSync(
    join(projectDir, 'app.mjs'),
    "import { run } from 'evil';\nawait run();\n",
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: an ESM dependency cannot bypass via named imports', () => {
  it('intercepts named imports of node:fs and node:child_process', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'app.mjs'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        NO_COLOR: '1',
        SECRET_FILE: join(projectDir, 'loot', '.env'),
      },
    });
    const output = `${result.stdout}\n${result.stderr}`;

    expect(output).toContain('FS-BLOCKED');
    expect(output).not.toContain('FS-READ');
    expect(output).toContain('FSP-BLOCKED');
    expect(output).not.toContain('FSP-READ');
    expect(output).toContain('SPAWN-BLOCKED');
    expect(output).not.toContain('SPAWN-RAN');
    expect(output).not.toContain('no monitored activity recorded');
  }, 60_000);
});
