import { resolveEnvPolicy } from './adapters/config/policy-loader.js';
import { buildMonitor } from './composition/build-monitor.js';
import { JsonlSinkReporter } from './adapters/reporting/jsonl-sink-reporter.js';

/**
 * The `--import dephawk/register` entrypoint.
 *
 * Runs during module evaluation so interceptors are installed *before* the
 * application's main module executes. The policy is resolved synchronously from
 * the environment (the CLI preloads any config file into `DEPHAWK_POLICY`),
 * which is why no async config import happens here — see docs/adr/0003.
 */
const INSTALLED = Symbol.for('dephawk.installed');
const globals = globalThis as Record<symbol, unknown>;

if (globals[INSTALLED] !== true) {
  globals[INSTALLED] = true;

  const policy = resolveEnvPolicy(process.env);
  const sinkPath = process.env['DEPHAWK_SINK'];

  if (sinkPath !== undefined && sinkPath.length > 0) {
    installGuardMode(sinkPath, policy);
  } else {
    installStandaloneMode(policy);
  }
}

/**
 * Standalone `run`: report on exit with the human console + HTML reporters.
 * These are async (HTML writes a file), so we drain on `beforeExit`.
 */
function installStandaloneMode(policy: ReturnType<typeof resolveEnvPolicy>): void {
  const monitor = buildMonitor({ policy });
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

  process.once('beforeExit', () => {
    void finish();
  });

  const onSignal = (code: number): void => {
    void finish().finally(() => process.exit(code));
  };
  process.once('SIGINT', () => onSignal(130));
  process.once('SIGTERM', () => onSignal(143));
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
): void {
  // Constructed before `start()`, so the sink's descriptor is opened while the
  // fs surface is still unpatched — dephawk writes through the descriptor and
  // the interceptors can then refuse the sink path to everyone, itself included.
  const reporter = new JsonlSinkReporter(sinkPath);
  const monitor = buildMonitor({
    policy,
    reporters: [reporter],
    protectedPaths: [sinkPath],
  });
  monitor.start();

  let flushed = false;
  const flush = (): void => {
    if (flushed) {
      return;
    }
    flushed = true;
    monitor.stop();
    reporter.report(monitor.snapshot()); // synchronous append
  };

  process.on('exit', flush);
  process.once('SIGINT', () => {
    flush();
    process.exit(130);
  });
  process.once('SIGTERM', () => {
    flush();
    process.exit(143);
  });
}
