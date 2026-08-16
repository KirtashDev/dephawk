#!/usr/bin/env node
import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { DhEvent } from './domain/event.js';
import {
  describeFailure,
  failsThreshold,
  isFailureThreshold,
  FAILURE_THRESHOLDS,
  type FailureThreshold,
} from './domain/failure-threshold.js';
import {
  diffBaseline,
  parseBaseline,
  recordBaseline,
  serializeBaseline,
  type BaselineDiff,
} from './domain/behaviour-baseline.js';
import { draftPolicy } from './domain/policy-draft.js';
import { PERMISSIVE_POLICY, type Mode } from './domain/policy.js';
import { DEPHAWK_CONFIG_BASENAMES } from './domain/protected-path.js';
import { FileConfigPolicyLoader } from './adapters/config/policy-loader.js';
import { renderConfig } from './adapters/config/render-config.js';
import { formatBaselineDiff } from './adapters/reporting/baseline-format.js';
import { ConsoleReporter } from './adapters/reporting/console-reporter.js';
import { HtmlReporter } from './adapters/reporting/html-reporter.js';
import { SarifReporter } from './adapters/reporting/sarif-reporter.js';
import { parseSink } from './adapters/reporting/jsonl-sink-reporter.js';
import { startMcpServer } from './adapters/mcp/server.js';
import { examinePackage } from './composition/examine-package.js';
import { detectExfilChains, detectTechnique } from './domain/threat.js';

/** Exit code when findings meet the `--fail-on` threshold. */
const FINDINGS_EXIT_CODE = 2;

const USAGE = `🦅 dephawk — watch what your dependencies do at runtime

Usage:
  dephawk run   [options] <command> [args...]
  dephawk guard [options] <command> [args...]
  dephawk init  [--out <path>] [--force] <command> [args...]
  dephawk x     <package>[@version] [--enforce] [--json]
  dephawk mcp

Commands:
  run     Monitor a command (e.g. your app or test run) and everything it
          spawns, then print ONE aggregated report.
  guard   The same, framed for an install (e.g. \`npm ci\`): it covers the
          dependency lifecycle scripts (pre/post-install) that run before your
          own code ever executes, which is where many real attacks fire.
  init    Watch a run and write the policy that would have let it pass, so you
          have something to edit instead of a blank file. It grants what it
          SAW — read the result before trusting it.
  x       Install a package in a throwaway sandbox, run it under dephawk, and
          report what it actually does — a one-shot audit of a single package
          (e.g. \`npx dephawk x some-suspicious-pkg\`).
  mcp     Run as an MCP server (stdio) so an AI coding agent can ask dephawk to
          audit what a command's dependencies do at runtime. Add it with
          \`claude mcp add dephawk -- npx -y dephawk mcp\`.

Modes:
  --observe (default)    record only, block nothing
  --enforce              block anything not permitted by policy
  (or set DEPHAWK_MODE=observe|enforce)

Options:
  --config <path>        policy file (default: dephawk.config.{js,mjs,cjs})
  --fail-on <level>      exit ${String(FINDINGS_EXIT_CODE)} when findings reach <level>:
                           none       never (default)
                           blocked    a call was actually prevented
                           violation  policy denied a call, blocked or not
                           sensitive  anything sensitive was touched
                           new        --replay found behaviour the baseline
                                      did not have
  --sarif <path>         also write SARIF 2.1.0 for GitHub code scanning
  --record <path>        write what this run did, to diff against later
  --replay <path>        report what changed since that recording
  --out <path>           where \`init\` writes the policy (default:
                         dephawk.config.js)
  --force                let \`init\` overwrite an existing policy file

Exit codes:
  0   clean, or below the --fail-on level
  ${String(FINDINGS_EXIT_CODE)}   findings reached --fail-on
  *   the command's own exit code, when it failed (that comes first)

Config:
  Looks for dephawk.config.{js,mjs,cjs} in the current directory,
  or pass --config <path>, or set DEPHAWK_CONFIG=<path>.

Examples:
  dephawk run npm test
  dephawk guard npm ci
  dephawk init npm test
  dephawk run --fail-on violation --sarif dephawk.sarif npm test
  dephawk run --record .dephawk/baseline.json npm test
  dephawk run --replay .dephawk/baseline.json --fail-on new npm test
  DEPHAWK_MODE=enforce dephawk guard npm install
`;

const CONFIG_NAMES = DEPHAWK_CONFIG_BASENAMES;

export async function run(argv: readonly string[]): Promise<number> {
  const subcommand = argv[0];
  if (subcommand === '--help' || subcommand === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (subcommand === 'mcp') {
    // Serve dephawk to an AI coding agent over the MCP stdio transport. stdout is
    // the protocol channel, so nothing else may write to it.
    const registerUrl = new URL('./register.js', import.meta.url).href;
    await startMcpServer({ version: toolVersion(), registerUrl });
    return 0;
  }
  if (subcommand === 'x') {
    return examineSubcommand(argv.slice(1));
  }
  if (subcommand !== 'run' && subcommand !== 'guard' && subcommand !== 'init') {
    process.stderr.write(USAGE);
    return 1;
  }

  const parsed = parseArgs(argv.slice(1));
  if (parsed === null) {
    return 1;
  }
  const { command, commandArgs, configOverride, modeOverride, failOn, sarifPath } =
    parsed;
  const { recordPath, replayPath } = parsed;
  if (recordPath !== undefined && replayPath !== undefined) {
    process.stderr.write(
      'dephawk: --record and --replay do the opposite jobs; pass one\n',
    );
    return 1;
  }
  if (failOn === 'new' && replayPath === undefined) {
    process.stderr.write(
      'dephawk: --fail-on new needs a baseline to compare against (--replay <path>)\n',
    );
    return 1;
  }
  const drafting = subcommand === 'init';

  const outPath = resolve(parsed.outPath ?? 'dephawk.config.js');
  if (drafting && existsSync(outPath) && !parsed.force) {
    process.stderr.write(
      `dephawk: ${outPath} already exists — pass --force to overwrite it\n`,
    );
    return 1;
  }

  // Resolve to an absolute path: it becomes `DEPHAWK_CONFIG` for the whole tree
  // and is matched against the absolute paths the fs interceptor sees, so a
  // relative `--config dephawk.config.js` must not stay relative.
  const configPath =
    configOverride !== null
      ? resolve(process.cwd(), configOverride)
      : discoverConfig(process.cwd(), process.env);
  // A --enforce/--observe flag takes precedence over the ambient DEPHAWK_MODE.
  const loaderEnv: NodeJS.ProcessEnv =
    modeOverride === undefined
      ? process.env
      : { ...process.env, DEPHAWK_MODE: modeOverride };
  // `init` deliberately ignores any existing config and never enforces: it is
  // learning what a run does, and a run that had calls blocked (or allowed by a
  // rule already written) would teach it the wrong thing.
  const policy = drafting
    ? PERMISSIVE_POLICY
    : await new FileConfigPolicyLoader({ configPath, env: loaderEnv }).load();

  // Resolve the sibling register.js next to this built CLI. As a file URL it is
  // safe to hand to `--import` (spaces are percent-encoded).
  const registerUrl = new URL('./register.js', import.meta.url).href;
  const nodeOptions = [process.env['NODE_OPTIONS'], `--import ${registerUrl}`]
    .filter((part) => part !== undefined && part.length > 0)
    .join(' ');

  // Every monitored process appends its events to one shared JSONL file (via
  // DEPHAWK_SINK, honoured by register.js) and the parent reports once, instead
  // of each process in the tree printing over the others. The parent holding
  // the events is also what lets it decide an exit code and write SARIF — the
  // command cannot gate anything it never sees.
  const sink = createSink();

  // The one baseline file this run touches — `--record` and `--replay` are
  // mutually exclusive (checked above) — resolved to an absolute path so the
  // interceptor's absolute paths match it.
  const baselineRaw = recordPath ?? replayPath;
  const baselinePath = baselineRaw === undefined ? null : resolve(baselineRaw);

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(modeOverride === undefined ? {} : { DEPHAWK_MODE: modeOverride }),
    ...(drafting ? { DEPHAWK_MODE: 'observe' } : {}),
    NODE_OPTIONS: nodeOptions,
    DEPHAWK_POLICY: JSON.stringify(policy),
    DEPHAWK_SINK: sink.path,
    // The resolved config path travels to the whole tree so `register.js` can
    // protect it: a dependency that rewrites `dephawk.config.js` grants itself
    // whatever it likes on the next run. Not while drafting — `init` is about to
    // write that file itself.
    ...(configPath !== null && !drafting ? { DEPHAWK_CONFIG: configPath } : {}),
    // The behaviour baseline, protected the same way. `--replay` reads it back
    // after the run to decide `--fail-on new`, so a dependency that overwrites
    // it mid-run — to add the very behaviour it just introduced — would hide
    // its own change from the diff. Reproduced: the gate passed on a poisoned
    // baseline. Covers `--record` too, so the file cannot be pre-seeded.
    ...(baselinePath === null ? {} : { DEPHAWK_BASELINE: baselinePath }),
  };

  const { code: exitCode, started } = await spawnMonitored(command, commandArgs, env);
  const events = drainSink(sink);

  // Nothing ran, so there is nothing to report on. Writing an empty report for
  // a command that never started would only be misleading.
  if (!started) {
    return exitCode;
  }

  if (drafting) {
    writeDraft(events, outPath);
    return exitCode;
  }

  await reportAggregate(events, {
    installGuard: subcommand === 'guard',
    sarifPath,
    mode: policy.mode,
  });

  if (recordPath !== undefined) {
    writeRecording(events, resolve(recordPath));
  }
  const diff = replayPath === undefined ? undefined : replay(events, resolve(replayPath));
  if (diff === null) {
    return 1;
  }
  const newBehaviours = diff?.added.length ?? 0;

  // A command that failed on its own terms reports that, whatever dephawk saw:
  // its failure is the more immediate thing to fix, and masking it would be a
  // lie about what happened.
  if (exitCode !== 0) {
    return exitCode;
  }
  if (failsThreshold(events, failOn, newBehaviours)) {
    process.stderr.write(
      `\ndephawk: failing — ${describeFailure(events, failOn, newBehaviours)} (--fail-on ${failOn})\n`,
    );
    return FINDINGS_EXIT_CODE;
  }
  return 0;
}

/** Canonicalisation shared by recording and replaying, so the two agree. */
function baselineOptions(): { rootPath: string; homeDir: string } {
  return { rootPath: process.cwd(), homeDir: safeHome() };
}

/** Snapshot what the run did, for a later `--replay` to diff against. */
function writeRecording(events: readonly DhEvent[], path: string): void {
  const baseline = recordBaseline(events, baselineOptions());
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, serializeBaseline(baseline), 'utf8');

  process.stderr.write(
    `\ndephawk: recorded ${String(baseline.behaviours.length)} behaviour${
      baseline.behaviours.length === 1 ? '' : 's'
    } to ${path}\n`,
  );
  process.stderr.write(
    '  Commit it. This records what your dependencies DO, not what is safe —\n' +
      '  recording an already-compromised tree makes its behaviour the norm.\n',
  );
}

/**
 * Compare the run against a recorded baseline, or null when it cannot be read.
 *
 * An unreadable baseline is an error rather than an empty comparison: silently
 * diffing against nothing would report "no change" for a run nobody checked.
 */
function replay(events: readonly DhEvent[], path: string): BaselineDiff | null {
  let contents: string;
  try {
    contents = readFileSync(path, 'utf8');
  } catch {
    process.stderr.write(
      `dephawk: cannot read the baseline at ${path} — record one first with --record\n`,
    );
    return null;
  }

  const baseline = parseBaseline(contents);
  if (baseline === null) {
    process.stderr.write(`dephawk: ${path} is not a dephawk baseline\n`);
    return null;
  }

  const diff = diffBaseline(baseline, events, baselineOptions());
  process.stderr.write(
    `\n${formatBaselineDiff(diff, { color: process.env['NO_COLOR'] === undefined })}`,
  );
  return diff;
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
  // Canonicalise the directory. `tmpdir()` is itself a symlink on macOS
  // (`/var` -> `/private/var`), so an un-resolved sink path never matches the
  // `realpath` of a link that points at it — which is how a dependency truncated
  // the audit log through a symlink alias the tamper check could not recognise.
  // Resolving here means the protected path and every `realpath` speak the same
  // canonical language.
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'dephawk-guard-')));
  return { directory, path: join(directory, 'events.jsonl') };
}

interface ParsedArgs {
  readonly command: string;
  readonly commandArgs: string[];
  readonly configOverride: string | null;
  readonly modeOverride: string | undefined;
  readonly failOn: FailureThreshold;
  readonly sarifPath: string | undefined;
  readonly outPath: string | undefined;
  readonly force: boolean;
  readonly recordPath: string | undefined;
  readonly replayPath: string | undefined;
}

/** Parse `[flags...] <command> [args...]`, or null (after printing an error). */
function parseArgs(input: readonly string[]): ParsedArgs | null {
  let args = [...input];
  let configOverride: string | null = null;
  let modeOverride: string | undefined;
  let failOn: FailureThreshold = 'none';
  let sarifPath: string | undefined;
  let outPath: string | undefined;
  let force = false;
  let recordPath: string | undefined;
  let replayPath: string | undefined;
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
    if (flag === '--fail-on') {
      const level = args[1];
      if (level === undefined || !isFailureThreshold(level)) {
        process.stderr.write(
          `dephawk: --fail-on expects one of ${FAILURE_THRESHOLDS.join(', ')}\n`,
        );
        return null;
      }
      failOn = level;
      args = args.slice(2);
      continue;
    }
    if (flag === '--sarif') {
      const path = args[1];
      if (path === undefined || path.startsWith('--')) {
        process.stderr.write('dephawk: --sarif expects a path\n');
        return null;
      }
      sarifPath = path;
      args = args.slice(2);
      continue;
    }
    if (flag === '--out') {
      const path = args[1];
      if (path === undefined || path.startsWith('--')) {
        process.stderr.write('dephawk: --out expects a path\n');
        return null;
      }
      outPath = path;
      args = args.slice(2);
      continue;
    }
    if (flag === '--force') {
      force = true;
      args = args.slice(1);
      continue;
    }
    if (flag === '--record' || flag === '--replay') {
      const path = args[1];
      if (path === undefined || path.startsWith('--')) {
        process.stderr.write(`dephawk: ${flag} expects a path\n`);
        return null;
      }
      if (flag === '--record') {
        recordPath = path;
      } else {
        replayPath = path;
      }
      args = args.slice(2);
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
  return {
    command,
    commandArgs: args.slice(1),
    configOverride,
    modeOverride,
    failOn,
    sarifPath,
    outPath,
    force,
    recordPath,
    replayPath,
  };
}

/**
 * Draft a policy from what the run did, and say plainly what that means.
 *
 * The warning is not boilerplate. Drafting from behaviour grants whatever was
 * observed, so a package that was already exfiltrating gets an allowlist entry
 * for its collector alongside the entries for your HTTP client — and the file
 * looks equally reasonable either way. Saying so at the moment of writing is
 * the only point where someone is definitely paying attention.
 */
function writeDraft(events: readonly DhEvent[], outPath: string): void {
  const draft = draftPolicy(events, { homeDir: safeHome() });
  writeFileSync(outPath, renderConfig(draft), 'utf8');

  const packages = Object.keys(draft.policy.packages);
  process.stderr.write(`\ndephawk: policy drafted at ${outPath}\n`);
  process.stderr.write(
    packages.length === 0
      ? '  Nothing needed a rule — the run touched nothing sensitive.\n'
      : `  ${String(packages.length)} package${packages.length === 1 ? '' : 's'} granted what they did: ${packages.join(', ')}\n`,
  );

  const review = draft.notes.filter((note) => note.needsReview.length > 0);
  if (review.length > 0) {
    process.stderr.write('  Open-ended grants worth checking first:\n');
    for (const note of review) {
      process.stderr.write(`    ${note.package}: ${note.needsReview.join(', ')}\n`);
    }
  }
  if (draft.unattributed.length > 0) {
    process.stderr.write(
      `  ${String(draft.unattributed.length)} finding${draft.unattributed.length === 1 ? '' : 's'} could not be attributed and were NOT granted — see the file.\n`,
    );
  }

  process.stderr.write(
    '  This grants what the run DID, not what is safe. Read it before you trust it.\n',
  );
}

function safeHome(): string {
  try {
    return homedir();
  } catch {
    return '';
  }
}

/** The outcome of trying to run the monitored command. */
interface SpawnOutcome {
  readonly code: number;
  /** False when the command could not be started at all. */
  readonly started: boolean;
}

/** Spawn the command with the monitored environment, resolving its exit code. */
function spawnMonitored(
  command: string,
  commandArgs: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<SpawnOutcome> {
  const child = spawn(command, commandArgs, { stdio: 'inherit', env });
  return new Promise<SpawnOutcome>((resolveOutcome) => {
    child.on('error', (error: Error) => {
      process.stderr.write(`dephawk: failed to start "${command}": ${error.message}\n`);
      resolveOutcome({ code: 127, started: false });
    });
    child.on('exit', (code, signal) => {
      resolveOutcome({ code: signal !== null ? 1 : (code ?? 0), started: true });
    });
  });
}

/** Read every event the monitored tree recorded, then remove the sink. */
function drainSink(sink: Sink): DhEvent[] {
  try {
    return existsSync(sink.path) ? parseSink(readFileSync(sink.path, 'utf8')) : [];
  } catch {
    return [];
  } finally {
    try {
      rmSync(sink.directory, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup of a temp directory — never fail the command over it.
    }
  }
}

interface ReportOptions {
  /** Say so when the run covered an install rather than a plain command. */
  readonly installGuard: boolean;
  readonly sarifPath: string | undefined;
  /** The mode the monitored tree ran in, so the report can advise accordingly. */
  readonly mode: Mode;
}

/** Print one aggregated report, and write the artifacts. */
async function reportAggregate(
  events: readonly DhEvent[],
  options: ReportOptions,
): Promise<void> {
  if (options.installGuard) {
    process.stderr.write(
      '\ndephawk: install guard — aggregated across every process spawned:\n',
    );
  }
  new ConsoleReporter({ mode: options.mode }).report(events);
  await new HtmlReporter().report(events);
  if (options.sarifPath !== undefined) {
    await new SarifReporter({
      outputPath: options.sarifPath,
      toolVersion: toolVersion(),
    }).report(events);
  }
}

/** dephawk's own version, for the SARIF tool driver. Best-effort. */
function toolVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * `dephawk x <package>[@version]` — install a package in a throwaway sandbox, run
 * it under dephawk, and report what it actually did. A shareable one-shot audit;
 * `--enforce` blocks anything sensitive, `--json` prints a machine summary.
 */
async function examineSubcommand(args: readonly string[]): Promise<number> {
  const enforce = args.includes('--enforce');
  const asJson = args.includes('--json');
  const spec = args.find((arg) => !arg.startsWith('--'));
  if (spec === undefined) {
    process.stderr.write('usage: dephawk x <package>[@version] [--enforce] [--json]\n');
    return 1;
  }
  const registerUrl = new URL('./register.js', import.meta.url).href;
  const mode: Mode = enforce ? 'enforce' : 'observe';
  process.stderr.write(
    `🦅 dephawk: installing and running ${spec} in a sandbox (${mode} mode — this executes the package)…\n`,
  );

  const result = await examinePackage(spec, { registerUrl, mode });
  if (!result.installed) {
    process.stderr.write(`dephawk: could not install ${spec}\n`);
    return 1;
  }

  const techniques = new Set<string>();
  for (const event of result.events) {
    const technique = detectTechnique(event.capability, event.detail);
    if (technique !== null) {
      techniques.add(technique);
    }
  }
  const exfil = detectExfilChains(result.events);

  if (asJson) {
    const findings = result.events
      .filter(
        (event) =>
          event.origin === 'dependency' &&
          (event.sensitive || detectTechnique(event.capability, event.detail) !== null),
      )
      .map((event) => ({
        package: event.package,
        capability: event.capability,
        detail: event.detail,
        technique: detectTechnique(event.capability, event.detail),
        blocked: event.blocked,
      }));
    process.stdout.write(
      `${JSON.stringify(
        {
          package: result.package,
          mode,
          recognisedTechniques: [...techniques].sort(),
          likelyCredentialExfiltration: exfil,
          findings,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  }

  process.stdout.write(`\n🦅 dephawk examined ${result.package}\n`);
  new ConsoleReporter({ mode, write: (text) => process.stdout.write(text) }).report(
    result.events,
  );
  return 0;
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

/**
 * Whether this module is the program being run, rather than an import.
 *
 * The comparison has to go through `realpath`. Every package manager installs a
 * `bin` as a **symlink** — `node_modules/.bin/dephawk`, the global bin
 * directory, npx's cache — so `process.argv[1]` is the link while
 * `import.meta.url` is the file it points at (Node resolves the main module's
 * real path unless `--preserve-symlinks-main`). Comparing the two directly was
 * false for every installed copy, which silently turned `npx dephawk …` and
 * `dephawk …` into a no-op: exit 0, no output, nothing monitored. It only ever
 * worked when invoked by path, which is how the test suite and `npm run demo`
 * invoke it — so nothing caught it.
 */
function isProgram(entry: string | undefined, moduleUrl: string): boolean {
  if (entry === undefined) {
    return false;
  }
  if (pathToFileURL(entry).href === moduleUrl) {
    return true;
  }
  try {
    return pathToFileURL(realpathSync(entry)).href === moduleUrl;
  } catch {
    return false; // the entry does not exist on disk (e.g. an eval'd program)
  }
}

if (isProgram(process.argv[1], import.meta.url)) {
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
