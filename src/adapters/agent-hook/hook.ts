/**
 * AI coding-agent hook integration: turn dephawk into an always-on install
 * guardrail for Claude Code, Cursor, Gemini CLI and Codex. `dephawk hooks
 * install` writes a pre-shell-command hook that runs `dephawk hook` before the
 * agent's shell commands; when the command is an unmonitored package install,
 * the hook refuses it and tells the agent to route it through dephawk instead.
 *
 * Every agent has its own hook dialect — config file, event name, payload shape
 * and deny format — so each is described once in {@link AGENTS} and everything
 * else is shared. Pure decision logic here; the CLI does the stdin/stdout and
 * the config file I/O.
 */

/** The agents dephawk can install its guardrail into. */
export type AgentKind = 'claude' | 'cursor' | 'gemini' | 'codex';

export const AGENT_KINDS: readonly AgentKind[] = ['claude', 'cursor', 'gemini', 'codex'];

/**
 * A hook payload, loosely typed on purpose: the union of what the four agents
 * send. Claude Code and Codex send `tool_name: 'Bash'` with
 * `tool_input.command`; Gemini CLI sends `tool_name: 'run_shell_command'` with
 * `tool_input.command`; Cursor's `beforeShellExecution` sends `command` at the
 * top level and no tool name.
 */
export interface HookPayload {
  readonly hook_event_name?: string;
  readonly tool_name?: string;
  readonly tool_input?: { readonly command?: unknown };
  readonly command?: unknown;
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

/**
 * Which agent sent a payload, from the event name each one uses. Claude Code
 * and Codex share `PreToolUse` and an identical output format, so telling them
 * apart is never needed: both resolve to `claude`'s dialect.
 */
export function detectAgent(payload: HookPayload): AgentKind {
  switch (payload.hook_event_name) {
    case 'beforeShellExecution':
      return 'cursor';
    case 'BeforeTool':
      return 'gemini';
    default:
      return 'claude';
  }
}

/** The shell command a payload is about to run, or null if it is not a shell call. */
export function shellCommandOf(agent: AgentKind, payload: HookPayload): string | null {
  let command: unknown;
  switch (agent) {
    case 'cursor':
      command = payload.command;
      break;
    case 'gemini':
      command =
        payload.tool_name === 'run_shell_command' ? payload.tool_input?.command : null;
      break;
    case 'claude':
    case 'codex':
      command = payload.tool_name === 'Bash' ? payload.tool_input?.command : null;
      break;
  }
  return typeof command === 'string' ? command : null;
}

const BLOCK_REASON =
  'This installs npm packages without monitoring — the moment an unvetted ' +
  'dependency runs its install scripts. Run it through dephawk so its runtime ' +
  'behaviour is watched: prefix the command with `dephawk guard ` (e.g. ' +
  '`dephawk guard npm ci`), or vet a single package first with ' +
  '`dephawk x <package>`.';

/** Decide whether to block a pre-shell-command hook payload and why. */
export function decideHook(
  payload: HookPayload,
  agent: AgentKind = detectAgent(payload),
): HookDecision {
  const command = shellCommandOf(agent, payload);
  if (command === null || !isUnmonitoredInstall(command)) {
    return { block: false };
  }
  return { block: true, reason: BLOCK_REASON };
}

/**
 * The agent-specific hook output for a decision, or null for "print nothing"
 * (an allow, for every agent that treats no output + exit 0 as "proceed").
 *
 * Cursor is the exception: it is installed with `failClosed`, so empty output
 * would block — it always gets an explicit `permission`.
 */
export function renderHookOutput(
  decision: HookDecision,
  agent: AgentKind = 'claude',
): string | null {
  switch (agent) {
    case 'cursor':
      return JSON.stringify(
        decision.block
          ? {
              continue: true,
              permission: 'deny',
              user_message: 'dephawk: unmonitored package install refused.',
              agent_message: decision.reason,
            }
          : { continue: true, permission: 'allow' },
      );
    case 'gemini':
      return decision.block
        ? JSON.stringify({ decision: 'deny', reason: decision.reason })
        : null;
    case 'claude':
    case 'codex':
      return decision.block
        ? JSON.stringify({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'deny',
              permissionDecisionReason: decision.reason,
            },
          })
        : null;
  }
}

/** Where an agent keeps its hook config, relative to the project or home dir. */
export interface AgentHookTarget {
  /** Path segments under the project root (local) or the home dir (global). */
  readonly file: readonly string[];
  /** One line for the user after a successful install. */
  readonly note: string;
}

export const AGENTS: Record<AgentKind, AgentHookTarget> = {
  claude: {
    file: ['.claude', 'settings.json'],
    note: 'Claude Code will now route `npm install`/`ci` (and pnpm/yarn/bun) through dephawk.',
  },
  cursor: {
    file: ['.cursor', 'hooks.json'],
    note: 'Cursor will now refuse unmonitored installs in agent mode (restart Cursor to load it).',
  },
  gemini: {
    file: ['.gemini', 'settings.json'],
    note: 'Gemini CLI will now refuse unmonitored installs (project hooks are reviewed on first run).',
  },
  codex: {
    file: ['.codex', 'hooks.json'],
    note: 'Codex will now refuse unmonitored installs — after you trust the hook once with /hooks.',
  },
};

/** A config object of unknown shape; only the keys we own are touched. */
export type HookConfig = Record<string, unknown>;

/**
 * True when a hook command is dephawk's own: it runs `… <cli>.js hook` or a
 * `dephawk … hook` bin, optionally with `--agent <name>` — specific enough to
 * recognise our own entry for an idempotent re-install.
 */
export function isDephawkHookCommand(command: unknown): boolean {
  if (typeof command !== 'string') {
    return false;
  }
  return (
    /\shook(\s+--agent\s+[a-z]+)?\s*$/.test(command.trim()) &&
    /dephawk|cli\.js/.test(command)
  );
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? [...value] : [];
}

function asRecord(value: unknown): HookConfig {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? { ...(value as HookConfig) }
    : {};
}

/** Replace our entry if present, else append it. */
function upsert(
  entries: unknown[],
  ours: unknown,
  isOurs: (entry: unknown) => boolean,
): unknown[] {
  const index = entries.findIndex(isOurs);
  if (index === -1) {
    entries.push(ours);
  } else {
    entries[index] = ours;
  }
  return entries;
}

/**
 * The Claude Code / Codex / Gemini CLI shape: `hooks.<event>` is a list of
 * `{ matcher, hooks: [{ type: 'command', command }] }` groups.
 */
function withMatcherGroupHook(
  config: HookConfig,
  event: string,
  matcher: string,
  hook: HookConfig,
): HookConfig {
  const hooks = asRecord(config['hooks']);
  const isOurs = (entry: unknown): boolean =>
    asArray(asRecord(entry)['hooks']).some((h) =>
      isDephawkHookCommand(asRecord(h)['command']),
    );
  hooks[event] = upsert(asArray(hooks[event]), { matcher, hooks: [hook] }, isOurs);
  return { ...config, hooks };
}

/**
 * Cursor's shape: `{ version: 1, hooks: { beforeShellExecution: [{ command, … }] } }`
 * — flat entries, no matcher groups.
 */
function withCursorHook(config: HookConfig, hookCommand: string): HookConfig {
  const hooks = asRecord(config['hooks']);
  const ours = {
    command: hookCommand,
    // Only package-manager commands reach dephawk at all, so the agent's other
    // shell calls pay nothing, and failing closed costs nothing for them.
    matcher: '\\b(npm|pnpm|yarn|bun)\\b',
    timeout: 10,
    failClosed: true,
  };
  hooks['beforeShellExecution'] = upsert(
    asArray(hooks['beforeShellExecution']),
    ours,
    (entry) => isDephawkHookCommand(asRecord(entry)['command']),
  );
  return { ...config, version: config['version'] ?? 1, hooks };
}

/**
 * Merge dephawk's guardrail hook into an agent's existing config object without
 * disturbing anything else. Idempotent: an existing dephawk entry is replaced
 * (its command refreshed). Returns a new object; the input is not mutated.
 */
export function withAgentHook(
  agent: AgentKind,
  config: HookConfig,
  hookCommand: string,
): HookConfig {
  switch (agent) {
    case 'claude':
    case 'codex':
      return withMatcherGroupHook(config, 'PreToolUse', 'Bash', {
        type: 'command',
        command: hookCommand,
      });
    case 'gemini':
      return withMatcherGroupHook(config, 'BeforeTool', 'run_shell_command', {
        type: 'command',
        name: 'dephawk',
        command: hookCommand,
        timeout: 10_000,
      });
    case 'cursor':
      return withCursorHook(config, hookCommand);
  }
}

/** Back-compat alias: the Claude Code merge, as 0.12 exported it. */
export function withDephawkHook(settings: HookConfig, hookCommand: string): HookConfig {
  return withAgentHook('claude', settings, hookCommand);
}

/** Parse `--agent claude,cursor` (or `all`) into a list; null on an unknown name. */
export function parseAgents(value: string | undefined): AgentKind[] | null {
  if (value === undefined) {
    return ['claude'];
  }
  if (value === 'all') {
    return [...AGENT_KINDS];
  }
  const names = value
    .split(',')
    .map((n) => n.trim().toLowerCase())
    .filter((n) => n !== '');
  if (names.length === 0 || !names.every((n) => (AGENT_KINDS as string[]).includes(n))) {
    return null;
  }
  return [...new Set(names)] as AgentKind[];
}
