/**
 * Keeping dephawk attached to the processes a monitored process starts.
 *
 * `dephawk run` and `dephawk guard` monitor a subtree by putting
 * `--import …/register.js` in `NODE_OPTIONS` and dephawk's own settings in
 * `DEPHAWK_*`, both of which children inherit. Inheritance is the whole
 * mechanism — and anything the monitored code can inherit, it can also decline
 * to pass on:
 *
 * ```js
 * const clean = { ...process.env };
 * delete clean.NODE_OPTIONS;
 * spawnSync(process.execPath, ['payload.js'], { env: clean });   // unwatched
 * ```
 *
 * The spawn itself is recorded, but everything the child does is invisible: no
 * interceptors were ever installed in it. Deleting the variables from
 * `process.env` and spawning with no explicit env does the same thing.
 *
 * These helpers are pure string/object transforms so the merge rules can be
 * tested without spawning anything.
 */
import { fileURLToPath } from 'node:url';

/** The parts of the environment that must reach every child process. */
export interface MonitoringEnv {
  /** `--import …` fragments that must appear in the child's `NODE_OPTIONS`. */
  readonly imports: readonly string[];
  /** `DEPHAWK_*` variables, captured before untrusted code could touch them. */
  readonly variables: Readonly<Record<string, string>>;
}

const IMPORT_FLAG = /--import(?:=|\s+)(\S+)/g;
const DEPHAWK_PREFIX = 'DEPHAWK_';

/**
 * Snapshot what monitoring needs from `env`.
 *
 * Taken once at install time, which is before any dependency has run, so the
 * snapshot is what dephawk was actually started with rather than whatever the
 * environment has been edited into by the time a spawn happens.
 *
 * `registerUrl` covers the `node --import dephawk/register app.js` form, where
 * the flag was passed on the command line and never appears in `NODE_OPTIONS`
 * for us to find.
 */
export function captureMonitoringEnv(
  env: NodeJS.ProcessEnv,
  registerUrl?: string,
): MonitoringEnv {
  const imports = [...(env['NODE_OPTIONS'] ?? '').matchAll(IMPORT_FLAG)].map(
    (match) => match[0],
  );

  if (registerUrl !== undefined && !imports.some((flag) => flag.includes(registerUrl))) {
    imports.push(`--import ${registerUrl}`);
  }

  const variables: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (key.startsWith(DEPHAWK_PREFIX) && value !== undefined) {
      variables[key] = value;
    }
  }

  return { imports, variables };
}

/**
 * The monitoring entries missing from `env`, read key by key.
 *
 * Used for the inherited-environment case, where the alternative — copying
 * `process.env` and patching the copy — would touch every variable in it. That
 * copy goes through the env interceptor's proxy, so it reports the package as
 * having read every secret in the environment merely because it spawned
 * something. Reading only the handful of names we care about avoids inventing
 * findings that never happened.
 */
export function missingMonitoring(
  env: NodeJS.ProcessEnv,
  monitoring: MonitoringEnv,
): readonly (readonly [string, string])[] {
  const missing: (readonly [string, string])[] = [];

  for (const [key, value] of Object.entries(monitoring.variables)) {
    if (env[key] !== value) {
      missing.push([key, value]);
    }
  }

  const nodeOptions = env['NODE_OPTIONS'] ?? '';
  const absent = monitoring.imports.filter((flag) => !nodeOptions.includes(flag));
  if (absent.length > 0) {
    missing.push([
      'NODE_OPTIONS',
      [nodeOptions, ...absent].filter((part) => part !== '').join(' '),
    ]);
  }

  return missing;
}

/** The outcome of putting monitoring back into a worker's options. */
export interface RestoredWorkerOptions {
  readonly options: Record<string, unknown>;
  /** What was missing and had to be put back (`execArgv`, `NODE_OPTIONS`, …). */
  readonly restored: readonly string[];
}

/**
 * Return `options` with monitoring guaranteed for a `worker_threads.Worker`, and
 * say what was put back. A copy — the caller's object is never mutated.
 *
 * A worker declines inheritance through two doors, and both had to be closed:
 *
 * ```js
 * new Worker('payload.js', { execArgv: [] })   // no --import: unmonitored
 * new Worker('payload.js', { env: {} })        // no NODE_OPTIONS: unmonitored
 * ```
 *
 * Only an *explicit* value can be short of anything: no `execArgv` inherits
 * `process.execArgv`, and no `env` (or `SHARE_ENV`) inherits the parent
 * environment, both of which already carry monitoring.
 */
export function restoreWorkerOptions(
  options: Record<string, unknown>,
  monitoring: MonitoringEnv,
  baseExecArgv: readonly string[] = [],
): RestoredWorkerOptions {
  const patched: Record<string, unknown> = { ...options };
  const restored: string[] = [];

  const execArgv = options['execArgv'];
  const explicit = Array.isArray(execArgv)
    ? execArgv.filter((arg): arg is string => typeof arg === 'string')
    : null;

  if (options['eval'] === true) {
    // An `eval: true` worker does not honour `--import` in execArgv — verified
    // on Node 20 and 22 — and with no execArgv it inherits `process.execArgv`,
    // whose `--import` is equally useless to it. So it runs entirely unmonitored
    // unless we switch to `--require`, which it does honour (register.js has no
    // top-level await, so it loads through `require`). We seed from whatever
    // execArgv would otherwise apply — the caller's, or the parent's — so any
    // other flags on it survive.
    const base = explicit ?? [...baseExecArgv];
    const missing = monitoring.imports
      .map(asRequireFlag)
      .filter((flag) => !base.some((arg) => arg.includes(requiredPath(flag))));
    if (missing.length > 0) {
      patched['execArgv'] = [...base, ...missing];
      restored.push('execArgv');
    }
  } else if (explicit !== null) {
    // A file-based worker with an explicit execArgv: `--import` works for it,
    // and only an explicit array can be missing the flag (no array inherits the
    // parent's, which already carries monitoring).
    const missing = monitoring.imports
      .map(asExecArgvFlag)
      .filter((flag) => !explicit.some((arg) => arg.includes(importedUrl(flag))));
    if (missing.length > 0) {
      patched['execArgv'] = [...explicit, ...missing];
      restored.push('execArgv');
    }
  }

  const env = options['env'];
  if (typeof env === 'object' && env !== null && !Array.isArray(env)) {
    const result = restoreMonitoring(env as NodeJS.ProcessEnv, monitoring);
    if (result.restored.length > 0) {
      patched['env'] = result.env;
      restored.push(...result.restored);
    }
  }

  return { options: patched, restored };
}

/**
 * `--import <url>` as a single `execArgv` entry. `NODE_OPTIONS` is one string
 * and tolerates the space-separated form; an argv array does not, because each
 * element is exactly one argument.
 */
function asExecArgvFlag(fragment: string): string {
  return `--import=${fragment.replace(/^--import(?:=|\s+)/, '')}`;
}

function importedUrl(flag: string): string {
  return flag.slice('--import='.length);
}

/**
 * `--require <path>` for an `eval` worker, which honours `--require` where it
 * ignores `--import`. The import fragment names a `file://` URL; `--require`
 * wants a filesystem path.
 */
function asRequireFlag(fragment: string): string {
  const url = fragment.replace(/^--import(?:=|\s+)/, '');
  const path = url.startsWith('file:') ? fileURLToPath(url) : url;
  return `--require=${path}`;
}

function requiredPath(flag: string): string {
  return flag.slice('--require='.length);
}

/** The outcome of putting monitoring back into an environment. */
export interface RestoredEnv {
  readonly env: NodeJS.ProcessEnv;
  /** Names that were missing or altered, and had to be put back. */
  readonly restored: readonly string[];
}

/**
 * Return `childEnv` with monitoring guaranteed present, and say what was put
 * back.
 *
 * Existing `NODE_OPTIONS` content is preserved and the missing `--import`
 * fragments appended, so a caller that sets its own flags keeps them. A caller
 * that deliberately built a minimal environment keeps that too — it just gains
 * dephawk, which is what being monitored means.
 */
export function restoreMonitoring(
  childEnv: NodeJS.ProcessEnv,
  monitoring: MonitoringEnv,
): RestoredEnv {
  const env: NodeJS.ProcessEnv = { ...childEnv };
  const restored: string[] = [];

  for (const [key, value] of Object.entries(monitoring.variables)) {
    if (env[key] !== value) {
      env[key] = value;
      restored.push(key);
    }
  }

  const nodeOptions = env['NODE_OPTIONS'] ?? '';
  const missing = monitoring.imports.filter((flag) => !nodeOptions.includes(flag));
  if (missing.length > 0) {
    env['NODE_OPTIONS'] = [nodeOptions, ...missing]
      .filter((part) => part !== '')
      .join(' ');
    restored.push('NODE_OPTIONS');
  }

  return { env, restored };
}
