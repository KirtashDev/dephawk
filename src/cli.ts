#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FileConfigPolicyLoader } from './adapters/config/policy-loader.js';

const USAGE = `🦅 dephawk — watch what your dependencies do at runtime

Usage:
  dephawk run [--config <path>] [--observe|--enforce] <command> [args...]

Modes:
  --observe (default)    record only, block nothing
  --enforce              block anything not permitted by policy
  (or set DEPHAWK_MODE=observe|enforce)

Config:
  Looks for dephawk.config.{js,mjs,cjs} in the current directory,
  or pass --config <path>, or set DEPHAWK_CONFIG=<path>.

Examples:
  dephawk run npm test
  DEPHAWK_MODE=enforce dephawk run node ./app.js
`;

const CONFIG_NAMES = ['dephawk.config.js', 'dephawk.config.mjs', 'dephawk.config.cjs'];

export async function run(argv: readonly string[]): Promise<number> {
  const subcommand = argv[0];
  if (subcommand === '--help' || subcommand === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (subcommand !== 'run') {
    process.stderr.write(USAGE);
    return 1;
  }

  let args = argv.slice(1);
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
    return 1;
  }

  const command = args[0];
  const commandArgs = args.slice(1);
  if (command === undefined) {
    process.stderr.write(`dephawk: no command given\n\n${USAGE}`);
    return 1;
  }

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

  const child = spawn(command, commandArgs, {
    stdio: 'inherit',
    env: {
      ...process.env,
      ...(modeOverride === undefined ? {} : { DEPHAWK_MODE: modeOverride }),
      NODE_OPTIONS: nodeOptions,
      DEPHAWK_POLICY: JSON.stringify(policy),
    },
  });

  return await new Promise<number>((resolveCode) => {
    child.on('error', (error: Error) => {
      process.stderr.write(`dephawk: failed to start "${command}": ${error.message}\n`);
      resolveCode(127);
    });
    child.on('exit', (code, signal) => {
      resolveCode(signal !== null ? 1 : (code ?? 0));
    });
  });
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
