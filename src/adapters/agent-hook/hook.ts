/**
 * Claude Code hook integration: turn dephawk into an always-on install guardrail
 * for an AI coding agent. `dephawk hooks install` writes a `PreToolUse` hook that
 * runs `dephawk hook` before every Bash command; when the command is an
 * unmonitored package install, the hook tells the agent to route it through
 * dephawk instead. Pure decision logic here; the CLI does the stdin/stdout and
 * the settings file I/O.
 */

/** The Claude Code PreToolUse payload we care about (loosely typed on purpose). */
export interface HookPayload {
  readonly tool_name?: string;
  readonly tool_input?: { readonly command?: string };
}

export interface HookDecision {
  readonly block: boolean;
  readonly reason?: string;
}

// npm / pnpm / yarn / bun install verbs. Word-bounded so "npm run installer"
// (a script called "installer") does not match.
const INSTALL_PATTERN =
  /\b(npm\s+(i|install|ci|add)|pnpm\s+(i|install|add)|yarn\s+(install|add)|bun\s+(i|install|add))\b/;

/**
 * True when the shell command installs packages but is not already going through
 * dephawk — the moment an agent pulls in code it has not vetted.
 */
export function isUnmonitoredInstall(command: string): boolean {
  if (!INSTALL_PATTERN.test(command)) {
    return false;
  }
  // Already routed through dephawk (`dephawk guard npm ci`, `dephawk x …`)? Let it be.
  return !/\bdephawk\b/.test(command);
}

/** Decide whether to block a PreToolUse Bash command and why. */
export function decideHook(payload: HookPayload): HookDecision {
  if (payload.tool_name !== 'Bash') {
    return { block: false };
  }
  const command = payload.tool_input?.command;
  if (typeof command !== 'string' || !isUnmonitoredInstall(command)) {
    return { block: false };
  }
  return {
    block: true,
    reason:
      'This installs npm packages without monitoring — the moment an unvetted ' +
      'dependency runs its install scripts. Run it through dephawk so its runtime ' +
      'behaviour is watched: prefix the command with `dephawk guard ` (e.g. ' +
      '`dephawk guard npm ci`), or vet a single package first with ' +
      '`dephawk x <package>`.',
  };
}

/**
 * The Claude Code `PreToolUse` output for a decision. A block is expressed as a
 * `deny` permission decision the agent will read and act on; an allow is empty
 * (Claude Code treats no output + exit 0 as "proceed").
 */
export function renderHookOutput(decision: HookDecision): string | null {
  if (!decision.block) {
    return null;
  }
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: decision.reason,
    },
  });
}

interface SettingsShape {
  hooks?: {
    PreToolUse?: Array<{
      matcher?: string;
      hooks?: Array<{ type?: string; command?: string }>;
    }>;
  };
  [key: string]: unknown;
}

/**
 * Merge dephawk's PreToolUse hook into an existing Claude Code settings object,
 * without disturbing anything else. Idempotent: an existing dephawk hook entry is
 * left as-is (its command refreshed). Returns a new object; the input is not
 * mutated.
 */
export function withDephawkHook(
  settings: SettingsShape,
  hookCommand: string,
): SettingsShape {
  const next: SettingsShape = { ...settings, hooks: { ...(settings.hooks ?? {}) } };
  const preToolUse = [...(next.hooks?.PreToolUse ?? [])];

  // dephawk's hook always runs `… <cli>.js hook` (or a `dephawk … hook` bin), so
  // it ends with the ` hook` subcommand and references dephawk's cli — specific
  // enough to recognise our own entry for an idempotent re-install.
  const isDephawk = (entry: { hooks?: Array<{ command?: string }> }): boolean =>
    (entry.hooks ?? []).some((h) => {
      const command = h.command ?? '';
      return command.trim().endsWith(' hook') && /dephawk|cli\.js/.test(command);
    });

  const dephawkEntry = {
    matcher: 'Bash',
    hooks: [{ type: 'command', command: hookCommand }],
  };

  const existingIndex = preToolUse.findIndex(isDephawk);
  if (existingIndex === -1) {
    preToolUse.push(dephawkEntry);
  } else {
    preToolUse[existingIndex] = dephawkEntry;
  }

  next.hooks = { ...next.hooks, PreToolUse: preToolUse };
  return next;
}
