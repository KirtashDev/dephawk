import { resolveEnvPolicy } from './adapters/config/policy-loader.js';
import { buildMonitor } from './composition/build-monitor.js';
import { JsonlSink } from './adapters/sink/jsonl-sink.js';
import { ConsoleReporter } from './adapters/reporting/console-reporter.js';
import { HtmlReporter } from './adapters/reporting/html-reporter.js';

/**
 * The `--import dephawk/register` entrypoint.
 *
 * Runs during module evaluation so interceptors are installed *before* the
 * application's main module executes. The policy is resolved synchronously from
 * the environment (the CLI preloads any config file into `DEPHAWK_POLICY`),
 * which is why no async config import happens here — see docs/adr/0003.
 */
const INSTALLED = Symbol.for('dephawk.installed');
/**
 * This module's own URL — the thing `--import` points at. Passed down so the
 * child-process interceptor can put it back into a child's environment when a
 * dependency strips monitoring out on the way past.
 */
const REGISTER_URL = import.meta.url;
const globals = globalThis as Record<symbol, unknown>;

if (globals[INSTALLED] !== true) {
  globals[INSTALLED] = true;

  const policy = resolveEnvPolicy(process.env);
  const sinkPath = process.env['DEPHAWK_SINK'];
  const protectedPaths = collectProtectedPaths(process.env);

  if (sinkPath !== undefined && sinkPath.length > 0) {
    installGuardMode(sinkPath, policy, protectedPaths);
  } else {
    installStandaloneMode(policy, protectedPaths);
  }
}

/**
 * Files that belong to dephawk, refused to every origin in both modes — see
 * {@link import('./domain/protected-path.js')}.
 *
 * The guard sink (`DEPHAWK_SINK`), the resolved config file (`DEPHAWK_CONFIG`)
 * and the behaviour baseline (`DEPHAWK_BASELINE`) — all absolute paths the CLI
 * sets so they reach the whole process tree. A dependency that could rewrite
 * `dephawk.config.js` would grant itself anything on the *next* run, and one
 * that could rewrite the baseline would hide its own new behaviour from
 * `--replay --fail-on new`. Nothing legitimate writes any of these from inside
 * a monitored program, so the write is refused rather than run through policy.
 * `dephawk init` writes the config, and the CLI writes the recording, both from
 * the un-monitored parent after the observed run has exited — never from here.
 */
function collectProtectedPaths(env: NodeJS.ProcessEnv): string[] {
  const paths = new Set<string>();
  for (const key of ['DEPHAWK_SINK', 'DEPHAWK_CONFIG', 'DEPHAWK_BASELINE'] as const) {
    const value = env[key];
    if (value === undefined || value.length === 0) {
      continue;
    }
    // Keep the value as given *and* its canonical (symlink-resolved) form. The
    // CLI canonicalises the sink, but the config and baseline are only
    // `path.resolve`d, so on a symlinked path (macOS `/tmp` -> `/private/tmp`,
    // `$TMPDIR` -> `/private/var/…`) a dependency could rewrite the same file
    // through its canonical name: the lexical tamper check missed it, and the
    // interceptor's realpath fallback then saw an already-canonical path resolve
    // to itself and let it pass. Protecting both spellings closes that — a write
    // via either name matches lexically, and a symlink alias still resolves into
    // the canonical one.
    paths.add(value);
    const canonical = canonicalise(value);
    if (canonical !== null) {
      paths.add(canonical);
    }
  }
  return [...paths];
}

/**
 * The canonical, symlink-resolved form of `target`, or null. Acquired through
 * `process.getBuiltinModule` — importing `node:fs` here would build its ESM
 * facade before the interceptors patch it, reopening the named-import bypass.
 * Falls back to resolving the parent directory when the file does not exist yet
 * (a `--record` baseline is written only after the run).
 */
function canonicalise(target: string): string | null {
  try {
    const fs = process.getBuiltinModule('node:fs');
    const realpath = fs.realpathSync.native ?? fs.realpathSync;
    try {
      return realpath(target);
    } catch {
      const path = process.getBuiltinModule('node:path');
      return path.join(realpath(path.dirname(target)), path.basename(target));
    }
  } catch {
    return null; // unresolvable — the as-given value still protects the direct path
  }
}

/**
 * Standalone `run`: report on exit with the human console + HTML reporters.
 *
 * The full report (console + the async HTML file) is drained on `beforeExit`.
 * But `beforeExit` does not fire when the program ends via `process.exit()` or a
 * hard crash — and a dependency can call `process.exit(0)` right after its
 * exfiltration to make the whole observe-mode report vanish, which is the only
 * signal in observe mode (calls are recorded, not blocked). The synchronous
 * `exit` event *does* fire in those cases, so the console report — the primary
 * signal — is rendered there too. The HTML file needs async I/O and cannot be
 * written from an `exit` handler, so it is best-effort; the console report is
 * what a dependency's `process.exit()` must not be able to erase. (`guard` mode
 * has no equivalent gap: it streams every event to the sink as it happens.)
 */
function installStandaloneMode(
  policy: ReturnType<typeof resolveEnvPolicy>,
  protectedPaths: readonly string[],
): void {
  const consoleReporter = new ConsoleReporter({ mode: policy.mode });
  const monitor = buildMonitor({
    policy,
    protectedPaths,
    registerUrl: REGISTER_URL,
    reporters: [consoleReporter, new HtmlReporter()],
  });
  monitor.start();

  let finished = false;
  const finish = async (): Promise<void> => {
    if (finished) {
      return;
    }
    finished = true;
    monitor.stop();
    await monitor.report();
  };

  const onBeforeExit = (): void => {
    void finish();
  };
  // Synchronous fallback for `process.exit()` / uncaught crash, which skip
  // `beforeExit`. Only the sync console reporter can run here; never throw.
  const onExit = (): void => {
    if (finished) {
      return;
    }
    finished = true;
    try {
      consoleReporter.report(monitor.snapshot());
    } catch {
      /* an exit handler must not throw */
    }
  };
  const onSignal = (code: number): void => {
    void finish().finally(() => process.exit(code));
  };
  const onSigint = (): void => onSignal(130);
  const onSigterm = (): void => onSignal(143);

  process.once('beforeExit', onBeforeExit);
  process.on('exit', onExit);
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);

  // In standalone mode the whole observe report is these listeners — and a
  // dependency can `process.removeAllListeners('exit')` (then `process.exit(0)`)
  // to strip them and vanish, exactly the blinding guard mode dodges by streaming
  // to its sink. Re-assert dephawk's own handlers after any listener removal so
  // the report still fires. (Reaching `EventEmitter.prototype` directly can still
  // bypass this — attribution is high-signal, not tamper-proof; see docs/adr/0002.)
  hardenExitListeners([
    ['beforeExit', onBeforeExit],
    ['exit', onExit],
    ['SIGINT', onSigint],
    ['SIGTERM', onSigterm],
  ]);
}

/**
 * Re-assert dephawk's own exit-family listeners after any
 * `removeAllListeners`/`removeListener`/`off` on `process`, so a dependency
 * cannot strip the report before exiting. The re-add is idempotent (the handlers
 * guard themselves with `finished`), so a normal teardown is unaffected.
 */
function hardenExitListeners(
  guarded: ReadonlyArray<readonly [string, (...args: unknown[]) => void]>,
): void {
  const proc = process as unknown as {
    listeners(event: string): unknown[];
    on(event: string, handler: (...args: unknown[]) => void): unknown;
  } & Record<string, unknown>;
  const reassert = (): void => {
    for (const [event, handler] of guarded) {
      if (!proc.listeners(event).includes(handler)) {
        proc.on(event, handler);
      }
    }
  };
  for (const key of ['removeAllListeners', 'removeListener', 'off'] as const) {
    const original = proc[key];
    if (typeof original !== 'function') {
      continue;
    }
    const bound = (original as (...args: unknown[]) => unknown).bind(proc);
    Object.defineProperty(proc, key, {
      configurable: true,
      writable: true,
      value: (...args: unknown[]): unknown => {
        const result = bound(...args);
        reassert();
        return result;
      },
    });
  }
}

/**
 * `guard` mode: append this process's events to the shared JSONL sink so the
 * parent aggregates them. The sink reporter is *synchronous*, so we flush on
 * the `exit` event — which fires even when a blocked call throws and crashes
 * the process (an uncaught exception still runs `exit` handlers). That is
 * exactly when we most want the record: an install-time capability was denied.
 */
function installGuardMode(
  sinkPath: string,
  policy: ReturnType<typeof resolveEnvPolicy>,
  protectedPaths: readonly string[],
): void {
  // Constructed before `start()`, so the sink's descriptor is opened while the
  // fs surface is still unpatched — dephawk writes through the descriptor and
  // the interceptors can then refuse the sink path to everyone, itself included.
  //
  // The sink writes each event as it is decided, not in a batch at exit. That
  // is deliberate and load-bearing: an `exit`-time flush can be cancelled by a
  // dependency calling `process.removeAllListeners('exit')`, which used to blind
  // the whole aggregated report and pass the `--fail-on` gate on an empty file.
  // With streaming, every event is durable the moment it happens, so tearing
  // down the exit handler loses nothing the parent has not already read.
  const sink = new JsonlSink(sinkPath);
  const monitor = buildMonitor({
    policy,
    sink,
    reporters: [],
    protectedPaths,
    registerUrl: REGISTER_URL,
  });
  monitor.start();

  // `stop()` only restores the built-ins; the record is already on disk. Kept
  // so a clean exit tears the interceptors down, but nothing depends on it
  // running for the events to survive.
  process.on('exit', () => monitor.stop());
  process.once('SIGINT', () => process.exit(130));
  process.once('SIGTERM', () => process.exit(143));
}
