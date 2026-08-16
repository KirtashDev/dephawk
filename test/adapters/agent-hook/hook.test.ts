import { describe, it, expect } from 'vitest';
import {
  decideHook,
  isUnmonitoredInstall,
  renderHookOutput,
  withDephawkHook,
} from '../../../src/adapters/agent-hook/hook.js';

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

describe('withDephawkHook — settings merge', () => {
  it('adds a Bash PreToolUse hook to empty settings', () => {
    const merged = withDephawkHook({}, 'node /x/cli.js hook');
    const entries = merged.hooks!.PreToolUse!;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.matcher).toBe('Bash');
    expect(entries[0]!.hooks![0]!.command).toContain('hook');
  });

  it('is idempotent — installing twice keeps one dephawk entry', () => {
    const once = withDephawkHook({}, 'node /x/cli.js hook');
    const twice = withDephawkHook(once, 'node /y/cli.js hook');
    expect(twice.hooks!.PreToolUse).toHaveLength(1);
    // The command is refreshed to the latest path.
    expect(twice.hooks!.PreToolUse![0]!.hooks![0]!.command).toContain('/y/');
  });

  it('preserves unrelated settings and other PreToolUse hooks', () => {
    const merged = withDephawkHook(
      {
        model: 'sonnet',
        hooks: {
          PreToolUse: [
            { matcher: 'Write', hooks: [{ type: 'command', command: 'other' }] },
          ],
        },
      },
      'node /x/cli.js hook',
    );
    expect(merged['model']).toBe('sonnet');
    expect(merged.hooks!.PreToolUse).toHaveLength(2);
  });
});
