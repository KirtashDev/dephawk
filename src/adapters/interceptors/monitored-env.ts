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
