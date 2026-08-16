import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DhEvent } from '../domain/event.js';
import type { Mode, Policy } from '../domain/policy.js';
import { parseSink } from '../adapters/reporting/jsonl-sink-reporter.js';

export interface AuditOptions {
  /** The policy the monitored tree runs under (serialised into `DEPHAWK_POLICY`). */
  readonly policy: Policy;
  /** `file://` URL of dephawk's `register.js`, injected via `--import`. */
  readonly registerUrl: string;
  /** Working directory for the command. Defaults to the current one. */
  readonly cwd?: string;
  /** `observe` (record only) or `enforce` (block). Defaults to the policy's mode. */
  readonly mode?: Mode;
}

export interface AuditOutcome {
  /** False when the command could not be spawned at all. */
  readonly started: boolean;
  /** The command's own exit code (1 for a signal). */
  readonly exitCode: number;
  /** Every capability event the monitored process tree recorded. */
  readonly events: DhEvent[];
}

/**
 * Run `command` under dephawk and return the events its dependencies produced —
 * the same mechanism as `dephawk run`, packaged for callers that want the
 * structured result rather than a printed report (the MCP server, tests).
 *
 * The child's own stdout/stderr are discarded: a caller like the MCP server owns
 * its stdout for the protocol, and the value here is the recorded behaviour, not
 * the command's console output. Events stream to a private temp JSONL sink that
 * is parsed and removed when the command exits.
 */
export async function auditCommand(
  command: string,
  args: readonly string[],
  options: AuditOptions,
): Promise<AuditOutcome> {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'dephawk-mcp-')));
  const sinkPath = join(directory, 'events.jsonl');
  const nodeOptions = [process.env['NODE_OPTIONS'], `--import ${options.registerUrl}`]
    .filter((part) => part !== undefined && part.length > 0)
    .join(' ');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_OPTIONS: nodeOptions,
    DEPHAWK_POLICY: JSON.stringify(options.policy),
    DEPHAWK_SINK: sinkPath,
    ...(options.mode === undefined ? {} : { DEPHAWK_MODE: options.mode }),
  };

  const outcome = await new Promise<{ code: number; started: boolean }>((resolve) => {
    const child = spawn(command, args, {
      // `ignore`, never `inherit`: the child must not write to the caller's
      // stdout (the MCP protocol channel) or block on a stdin no one feeds.
      stdio: 'ignore',
      env,
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    });
    child.on('error', () => resolve({ code: 127, started: false }));
    child.on('exit', (code, signal) =>
      resolve({ code: signal !== null ? 1 : (code ?? 0), started: true }),
    );
  });

  let events: DhEvent[] = [];
  try {
    if (existsSync(sinkPath)) {
      events = parseSink(readFileSync(sinkPath, 'utf8'));
    }
  } catch {
    events = [];
  } finally {
    try {
      rmSync(directory, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup of a temp directory.
    }
  }

  return { started: outcome.started, exitCode: outcome.code, events };
}
