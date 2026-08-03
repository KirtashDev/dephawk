#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { DhEvent } from './domain/event.js';
import { FileConfigPolicyLoader } from './adapters/config/policy-loader.js';
import { ConsoleReporter } from './adapters/reporting/console-reporter.js';
import { HtmlReporter } from './adapters/reporting/html-reporter.js';
import { parseSink } from './adapters/reporting/jsonl-sink-reporter.js';

const USAGE = `🦅 dephawk — watch what your dependencies do at runtime

Usage:
  dephawk run   [--config <path>] [--observe|--enforce] <command> [args...]
  dephawk guard [--config <path>] [--observe|--enforce] <command> [args...]

Commands:
  run     Monitor a single command (e.g. your app or test run).
  guard   Monitor an install (e.g. \`npm ci\`) and every Node process it
          spawns — including dependency lifecycle scripts (pre/post-install) —
          then print ONE aggregated report. Catches attacks that run at
          install time, before your own code ever executes.

Modes:
  --observe (default)    record only, block nothing
  --enforce              block anything not permitted by policy
  (or set DEPHAWK_MODE=observe|enforce)

Config:
  Looks for dephawk.config.{js,mjs,cjs} in the current directory,
  or pass --config <path>, or set DEPHAWK_CONFIG=<path>.

Examples:
  dephawk run npm test
  dephawk guard npm ci
  DEPHAWK_MODE=enforce dephawk guard npm install
`;

const CONFIG_NAMES = ['dephawk.config.js', 'dephawk.config.mjs', 'dephawk.config.cjs'];

export async function run(argv: readonly string[]): Promise<number> {
  const subcommand = argv[0];
  if (subcommand === '--help' || subcommand === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (subcommand !== 'run' && subcommand !== 'guard') {
    process.stderr.write(USAGE);
    return 1;
  }

  const parsed = parseArgs(argv.slice(1));
  if (parsed === null) {
    return 1;
  }
  const { command, commandArgs, configOverride, modeOverride } = parsed;

  const configPath = configOverride ?? discoverConfig(process.cwd(), process.env);
  // A --enforce/--observe flag takes precedence over the ambient DEPHAWK_MODE.
  const loaderEnv: NodeJS.ProcessEnv =
    modeOverride === undefined
      ? process.env
      : { ...process.env, DEPHAWK_MODE: modeOverride };
  const policy = await new FileConfigPolicyLoader({
    configPath,
    env: loaderEnv,
  }).load();

  // Resolve the sibling register.js next to this built CLI. As a file URL it is
  // safe to hand to `--import` (spaces are percent-encoded).
  const registerUrl = new URL('./register.js', import.meta.url).href;
  const nodeOptions = [process.env['NODE_OPTIONS'], `--import ${registerUrl}`]
    .filter((part) => part !== undefined && part.length > 0)
    .join(' ');

  // In `guard` mode, every spawned process appends its events to one shared
  // JSONL file (via DEPHAWK_SINK, honoured by register.js) so the parent can
  // print a single aggregated report instead of each process reporting itself.
  const sink = subcommand === 'guard' ? createSink() : undefined;

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(modeOverride === undefined ? {} : { DEPHAWK_MODE: modeOverride }),
    NODE_OPTIONS: nodeOptions,
    DEPHAWK_POLICY: JSON.stringify(policy),
    ...(sink === undefined ? {} : { DEPHAWK_SINK: sink.path }),
  };

  const exitCode = await spawnMonitored(command, commandArgs, env);

  if (sink !== undefined) {
    await reportAggregate(sink);
  }

  return exitCode;
}

interface Sink {
  readonly directory: string;
  readonly path: string;
}

/**
 * Create the shared event sink inside a fresh private directory.
 *
 * `mkdtemp` matters here. The old name — `dephawk-guard-<pid>-<now>.jsonl`
 * directly in the world-writable temp directory — was guessable: the pid is
 * public and the timestamp spans a few thousand candidates, so anyone with an
 * account on the machine could pre-create every one of them as a symlink and
 * have the guard append attacker-chosen content to a file of their choosing.
 * `mkdtemp` returns an unguessable name and creates the directory 0700, so
 * neither the directory nor the file inside it can be squatted.
 */
function createSink(): Sink {
  const directory = mkdtempSync(join(tmpdir(), 'dephawk-guard-'));
  return { directory, path: join(directory, 'events.jsonl') };
}

interface ParsedArgs {
  readonly command: string;
  readonly commandArgs: string[];
  readonly configOverride: string | null;
  readonly modeOverride: string | undefined;
}

/** Parse `[flags...] <command> [args...]`, or null (after printing an error). */
function parseArgs(input: readonly string[]): ParsedArgs | null {
  let args = [...input];
  let configOverride: string | null = null;
  let modeOverride: string | undefined;
  while (args[0] !== undefined && args[0].startsWith('--')) {
    const flag = args[0];
    if (flag === '--') {
      args = args.slice(1);
      break;
    }
    if (flag === '--config') {
      configOverride = args[1] ?? null;
      args = args.slice(2);
      continue;
    }
    if (flag === '--enforce' || flag === '--observe') {
      modeOverride = flag.slice(2);
      args = args.slice(1);
      continue;
    }
    process.stderr.write(`dephawk: unknown option ${flag}\n\n${USAGE}`);
    return null;
  }

  const command = args[0];
  if (command === undefined) {
    process.stderr.write(`dephawk: no command given\n\n${USAGE}`);
    return null;
  }
  return { command, commandArgs: args.slice(1), configOverride, modeOverride };
}

/** Spawn the command with the monitored environment, resolving its exit code. */
function spawnMonitored(
  command: string,
  commandArgs: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const child = spawn(command, commandArgs, { stdio: 'inherit', env });
  return new Promise<number>((resolveCode) => {
    child.on('error', (error: Error) => {
      process.stderr.write(`dephawk: failed to start "${command}": ${error.message}\n`);
      resolveCode(127);
    });
    child.on('exit', (code, signal) => {
      resolveCode(signal !== null ? 1 : (code ?? 0));
    });
  });
}

/** Read the shared sink, print one aggregated report, then remove it. */
async function reportAggregate(sink: Sink): Promise<void> {
  let events: DhEvent[] = [];
  try {
    events = existsSync(sink.path) ? parseSink(readFileSync(sink.path, 'utf8')) : [];
  } catch {
    events = [];
  } finally {
    try {
      rmSync(sink.directory, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup of a temp directory — never fail the command over it.
    }
  }

  process.stderr.write(
    '\ndephawk: install guard — aggregated across every process spawned:\n',
  );
  new ConsoleReporter().report(events);
  await new HtmlReporter().report(events);
}

function discoverConfig(cwd: string, env: NodeJS.ProcessEnv): string | null {
  const fromEnv = env['DEPHAWK_CONFIG'];
  if (fromEnv !== undefined && fromEnv.length > 0) {
    return resolve(cwd, fromEnv);
  }
  for (const name of CONFIG_NAMES) {
    const candidate = resolve(cwd, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

// Only run when executed as a program (not when imported by tests).
const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  run(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`dephawk: ${message}\n`);
      process.exitCode = 1;
    });
}
