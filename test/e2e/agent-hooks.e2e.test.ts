import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// `dephawk hooks install --agent …` through the real CLI: the config each agent
// reads is written in that agent's shape, and the installed command, fed the
// payload that agent documents, refuses an unmonitored install in that agent's
// own deny dialect.
const cliPath = resolve('dist/cli.js');
const projectDir = join(tmpdir(), `dephawk-agent-hooks-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  mkdirSync(join(projectDir, '.gemini'), { recursive: true });
  // An existing Gemini config the install must keep.
  writeFileSync(
    join(projectDir, '.gemini', 'settings.json'),
    JSON.stringify({ theme: 'GitHub' }),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function readJson(...segments: string[]): Record<string, unknown> {
  return JSON.parse(readFileSync(join(projectDir, ...segments), 'utf8')) as Record<
    string,
    unknown
  >;
}

/** Run an installed hook command the way the agent would: payload on stdin. */
function runHook(command: string, payload: unknown): string {
  // Through a shell, as every agent runs it — so the quoting is exercised too.
  const result = spawnSync(command, {
    shell: true,
    input: typeof payload === 'string' ? payload : JSON.stringify(payload),
    encoding: 'utf8',
  });
  expect(result.status).toBe(0);
  return result.stdout;
}

describe('e2e: dephawk hooks install --agent all', () => {
  it('writes every agent’s config and each hook denies in its own dialect', () => {
    const install = spawnSync(
      process.execPath,
      [cliPath, 'hooks', 'install', '--agent', 'all'],
      { cwd: projectDir, encoding: 'utf8' },
    );
    expect(install.status).toBe(0);

    // Claude Code + Codex: PreToolUse / Bash.
    for (const file of [
      ['.claude', 'settings.json'],
      ['.codex', 'hooks.json'],
    ]) {
      const config = readJson(...file) as { hooks: { PreToolUse: Group[] } };
      const command = config.hooks.PreToolUse[0]!.hooks[0]!.command;
      const out = JSON.parse(
        runHook(command, { tool_name: 'Bash', tool_input: { command: 'npm i x' } }),
      ) as { hookSpecificOutput: { permissionDecision: string } };
      expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    }

    // Gemini CLI: BeforeTool / run_shell_command, existing settings kept.
    const gemini = readJson('.gemini', 'settings.json') as {
      theme: string;
      hooks: { BeforeTool: Group[] };
    };
    expect(gemini.theme).toBe('GitHub');
    const geminiOut = JSON.parse(
      runHook(gemini.hooks.BeforeTool[0]!.hooks[0]!.command, {
        hook_event_name: 'BeforeTool',
        tool_name: 'run_shell_command',
        tool_input: { command: 'pnpm add x' },
      }),
    ) as { decision: string };
    expect(geminiOut.decision).toBe('deny');

    // Cursor: beforeShellExecution, explicit allow for a non-install.
    const cursor = readJson('.cursor', 'hooks.json') as {
      version: number;
      hooks: { beforeShellExecution: { command: string }[] };
    };
    expect(cursor.version).toBe(1);
    const cursorCommand = cursor.hooks.beforeShellExecution[0]!.command;
    const denied = JSON.parse(
      runHook(cursorCommand, {
        hook_event_name: 'beforeShellExecution',
        command: 'yarn add x',
      }),
    ) as { permission: string };
    expect(denied.permission).toBe('deny');
    const allowed = JSON.parse(
      runHook(cursorCommand, {
        hook_event_name: 'beforeShellExecution',
        command: 'npm test',
      }),
    ) as { permission: string };
    expect(allowed.permission).toBe('allow');
    // Fail-closed agent, garbage payload: still an explicit allow, never silence.
    expect(JSON.parse(runHook(cursorCommand, 'not json')).permission).toBe('allow');
  }, 60_000);

  it('is idempotent across re-installs', () => {
    spawnSync(process.execPath, [cliPath, 'hooks', 'install', '--agent', 'all'], {
      cwd: projectDir,
    });
    const cursor = readJson('.cursor', 'hooks.json') as {
      hooks: { beforeShellExecution: unknown[] };
    };
    expect(cursor.hooks.beforeShellExecution).toHaveLength(1);
    const claude = readJson('.claude', 'settings.json') as {
      hooks: { PreToolUse: unknown[] };
    };
    expect(claude.hooks.PreToolUse).toHaveLength(1);
  }, 60_000);

  it('rejects an unknown agent without writing anything', () => {
    const result = spawnSync(
      process.execPath,
      [cliPath, 'hooks', 'install', '--agent', 'copilot'],
      { cwd: projectDir, encoding: 'utf8' },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/unknown agent/);
  });
});

interface Group {
  hooks: { command: string }[];
}
