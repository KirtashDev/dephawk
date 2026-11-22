import { describe, it, expect } from 'vitest';
import {
  decideHook,
  detectAgent,
  isDephawkHookCommand,
  isUnmonitoredInstall,
  parseAgents,
  renderHookOutput,
  withAgentHook,
  withDephawkHook,
} from '../../../src/adapters/agent-hook/hook.js';
import type { HookConfig } from '../../../src/adapters/agent-hook/hook.js';

interface Group {
  matcher?: string;
  hooks?: { type?: string; command?: string; name?: string }[];
}

/** The matcher groups under `hooks.<event>` — typed for the assertions only. */
function groups(config: HookConfig, event: string): Group[] {
  return ((config['hooks'] as Record<string, unknown>)[event] ?? []) as Group[];
}

describe('isUnmonitoredInstall', () => {
  it.each([
    'npm install',
    'npm i left-pad',
    'npm ci',
    'npm add foo',
    'pnpm install',
    'pnpm add foo',
    'yarn add foo',
    'yarn install',
    'bun install',
    'bun add foo',
    'cd app && npm ci',
  ])('flags %s', (command) => {
    expect(isUnmonitoredInstall(command)).toBe(true);
  });

  it.each([
    'dephawk guard npm ci', // already monitored
    'dephawk x left-pad',
    'npm run build', // a script, not an install
    'npm run installer',
    'npm test',
    'ls -la',
    'node index.js',
  ])('does not flag %s', (command) => {
    expect(isUnmonitoredInstall(command)).toBe(false);
  });
});

describe('decideHook', () => {
  it('blocks an unmonitored install with actionable guidance', () => {
    const decision = decideHook({
      tool_name: 'Bash',
      tool_input: { command: 'npm install left-pad' },
    });
    expect(decision.block).toBe(true);
    expect(decision.reason).toMatch(/dephawk guard/);
  });

  it('allows a non-Bash tool', () => {
    expect(
      decideHook({ tool_name: 'Read', tool_input: { command: 'npm install' } }).block,
    ).toBe(false);
  });

  it('allows a Bash command that is not an install', () => {
    expect(decideHook({ tool_name: 'Bash', tool_input: { command: 'ls' } }).block).toBe(
      false,
    );
  });

  it('allows when the payload has no command', () => {
    expect(decideHook({ tool_name: 'Bash' }).block).toBe(false);
  });
});

describe('renderHookOutput', () => {
  it('emits a PreToolUse deny for a block', () => {
    const output = renderHookOutput({ block: true, reason: 'nope' });
    const parsed = JSON.parse(output!) as {
      hookSpecificOutput: { hookEventName: string; permissionDecision: string };
    };
    expect(parsed.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('emits nothing for an allow', () => {
    expect(renderHookOutput({ block: false })).toBeNull();
  });
});

describe('withDephawkHook — Claude Code settings merge', () => {
  it('adds a Bash PreToolUse hook to empty settings', () => {
    const entries = groups(withDephawkHook({}, 'node /x/cli.js hook'), 'PreToolUse');
    expect(entries).toHaveLength(1);
    expect(entries[0]!.matcher).toBe('Bash');
    expect(entries[0]!.hooks![0]!.command).toContain('hook');
  });

  it('is idempotent — installing twice keeps one dephawk entry', () => {
    const once = withDephawkHook({}, 'node /x/cli.js hook');
    const twice = withDephawkHook(once, 'node /y/cli.js hook');
    expect(groups(twice, 'PreToolUse')).toHaveLength(1);
    // The command is refreshed to the latest path.
    expect(groups(twice, 'PreToolUse')[0]!.hooks![0]!.command).toContain('/y/');
  });

  it('preserves unrelated settings and other PreToolUse hooks', () => {
    const merged = withDephawkHook(
      {
        model: 'sonnet',
        hooks: {
          PreToolUse: [
            { matcher: 'Write', hooks: [{ type: 'command', command: 'other' }] },
          ],
          Stop: [{ hooks: [{ type: 'command', command: 'notify' }] }],
        },
      },
      'node /x/cli.js hook',
    );
    expect(merged['model']).toBe('sonnet');
    expect(groups(merged, 'PreToolUse')).toHaveLength(2);
    expect(groups(merged, 'Stop')).toHaveLength(1);
  });

  it('does not mutate its input', () => {
    const input: HookConfig = { hooks: { PreToolUse: [] } };
    withDephawkHook(input, 'node /x/cli.js hook');
    expect(groups(input, 'PreToolUse')).toHaveLength(0);
  });
});

// Payloads as each agent documents them (late 2026).
const CURSOR = {
  hook_event_name: 'beforeShellExecution',
  command: 'npm install left-pad',
  cwd: '/repo',
};
const GEMINI = {
  hook_event_name: 'BeforeTool',
  tool_name: 'run_shell_command',
  tool_input: { command: 'pnpm add left-pad' },
};
const CODEX = {
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'yarn add left-pad' },
};

describe('detectAgent — from the event name each agent sends', () => {
  it('tells Cursor and Gemini apart; Claude and Codex share a dialect', () => {
    expect(detectAgent(CURSOR)).toBe('cursor');
    expect(detectAgent(GEMINI)).toBe('gemini');
    expect(detectAgent(CODEX)).toBe('claude');
    expect(detectAgent({})).toBe('claude');
  });
});

describe('decideHook — every agent', () => {
  it.each([
    ['cursor', CURSOR],
    ['gemini', GEMINI],
    ['codex', CODEX],
  ] as const)('blocks an unmonitored install from %s', (_name, payload) => {
    expect(decideHook(payload).block).toBe(true);
  });

  it('allows the same installs once routed through dephawk', () => {
    expect(decideHook({ ...CURSOR, command: 'dephawk guard npm install' }).block).toBe(
      false,
    );
    expect(
      decideHook({ ...GEMINI, tool_input: { command: 'dephawk guard pnpm add x' } })
        .block,
    ).toBe(false);
  });

  it('ignores Gemini tools that are not the shell', () => {
    expect(
      decideHook({ ...GEMINI, tool_name: 'write_file', tool_input: { command: 'npm i' } })
        .block,
    ).toBe(false);
  });

  it('ignores a non-string command', () => {
    expect(decideHook({ ...CURSOR, command: ['npm', 'i'] }).block).toBe(false);
  });
});

describe('renderHookOutput — each agent’s deny dialect', () => {
  const deny = { block: true, reason: 'route it through dephawk' };

  it('Cursor: permission deny with the reason for the agent', () => {
    const out = JSON.parse(renderHookOutput(deny, 'cursor')!) as Record<string, unknown>;
    expect(out['permission']).toBe('deny');
    expect(out['agent_message']).toBe('route it through dephawk');
  });

  it('Cursor: an explicit allow, since it is installed fail-closed', () => {
    const out = JSON.parse(renderHookOutput({ block: false }, 'cursor')!) as Record<
      string,
      unknown
    >;
    expect(out['permission']).toBe('allow');
  });

  it('Gemini: decision deny + reason, nothing on allow', () => {
    expect(JSON.parse(renderHookOutput(deny, 'gemini')!)).toEqual({
      decision: 'deny',
      reason: 'route it through dephawk',
    });
    expect(renderHookOutput({ block: false }, 'gemini')).toBeNull();
  });

  it('Codex: the PreToolUse permissionDecision, like Claude Code', () => {
    expect(renderHookOutput(deny, 'codex')).toBe(renderHookOutput(deny, 'claude'));
  });
});

describe('withAgentHook — each agent’s config shape', () => {
  it('Codex: Bash PreToolUse group, like Claude Code', () => {
    const entries = groups(
      withAgentHook('codex', {}, 'node cli.js hook --agent codex'),
      'PreToolUse',
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.matcher).toBe('Bash');
  });

  it('Gemini: BeforeTool group on run_shell_command, keeping other settings', () => {
    const merged = withAgentHook(
      'gemini',
      { theme: 'dark', mcpServers: { a: {} } },
      'node cli.js hook --agent gemini',
    );
    const entries = groups(merged, 'BeforeTool');
    expect(entries[0]!.matcher).toBe('run_shell_command');
    expect(entries[0]!.hooks![0]!.name).toBe('dephawk');
    expect(merged['theme']).toBe('dark');
    expect(merged['mcpServers']).toEqual({ a: {} });
  });

  it('Cursor: version 1, flat fail-closed entry, idempotent', () => {
    const once = withAgentHook('cursor', {}, '/n /a/cli.js hook --agent cursor');
    const twice = withAgentHook('cursor', once, '/n /b/cli.js hook --agent cursor');
    expect(twice['version']).toBe(1);
    const entries = (twice['hooks'] as Record<string, unknown>)[
      'beforeShellExecution'
    ] as Record<string, unknown>[];
    expect(entries).toHaveLength(1);
    expect(entries[0]!['failClosed']).toBe(true);
    expect(entries[0]!['command']).toContain('/b/');
  });

  it('Cursor: keeps an existing version and other hooks', () => {
    const merged = withAgentHook(
      'cursor',
      {
        version: 1,
        hooks: { beforeShellExecution: [{ command: './guard.sh' }], stop: [] },
      },
      '/n /a/cli.js hook --agent cursor',
    );
    const hooks = merged['hooks'] as Record<string, unknown[]>;
    expect(hooks['beforeShellExecution']).toHaveLength(2);
    expect(hooks['stop']).toEqual([]);
  });
});

describe('isDephawkHookCommand', () => {
  it.each([
    '/usr/bin/node /x/dephawk/dist/cli.js hook',
    '/usr/bin/node /x/dist/cli.js hook --agent cursor',
    'npx dephawk hook',
    '"/usr/bin/node" "/My Projects/dephawk/dist/cli.js" hook --agent gemini',
  ])('recognises %s', (command) => {
    expect(isDephawkHookCommand(command)).toBe(true);
  });

  it.each(['./guard.sh', 'node other.js hook', 'dephawk guard npm ci', 42])(
    'does not claim %s',
    (command) => {
      expect(isDephawkHookCommand(command)).toBe(false);
    },
  );
});

describe('parseAgents', () => {
  it('defaults to Claude Code', () => {
    expect(parseAgents(undefined)).toEqual(['claude']);
  });
  it('accepts a list and all', () => {
    expect(parseAgents('cursor, Gemini,cursor')).toEqual(['cursor', 'gemini']);
    expect(parseAgents('all')).toEqual(['claude', 'cursor', 'gemini', 'codex']);
  });
  it('rejects an unknown name', () => {
    expect(parseAgents('copilot')).toBeNull();
    expect(parseAgents('')).toBeNull();
  });
});
