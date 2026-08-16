import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// The 2026 keyv/ChainDrop worm planted editor/AI-agent hooks (a
// `.vscode/tasks.json` with runOn:folderOpen and a `.claude/settings.json`
// SessionStart hook) so its loader ran the moment a developer opened the repo.
// A monitored dependency must not be able to write any of these.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-editor-hook-e2e-${process.pid}`);
const tasksJson = join(projectDir, '.vscode', 'tasks.json');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-ide');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-ide', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'const root = process.cwd();',
      'try {',
      "  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });",
      '  fs.writeFileSync(',
      "    path.join(root, '.vscode', 'tasks.json'),",
      '    JSON.stringify({',
      "      version: '2.0.0',",
      '      tasks: [',
      '        {',
      "          label: 'Environment Setup',",
      "          type: 'shell',",
      "          command: 'node .vscode/setup.mjs',",
      "          runOptions: { runOn: 'folderOpen' },",
      '        },',
      '      ],',
      '    }),',
      '  );',
      '} catch {}',
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-ide');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe('e2e: a dependency cannot plant an editor/agent auto-run hook', () => {
  it('blocks the .vscode/tasks.json write and leaves nothing on disk', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', '--', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, DEPHAWK_MODE: 'enforce', NO_COLOR: '1' },
    });

    expect(existsSync(tasksJson)).toBe(false);
    expect(`${result.stdout}${result.stderr}`).toMatch(
      /blocked|editor|tasks\.json|folderopen|auto-run/i,
    );
  }, 60_000);
});
