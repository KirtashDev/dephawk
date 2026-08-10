import { resolveEnvPolicy } from './adapters/config/policy-loader.js';
import { buildMonitor } from './composition/build-monitor.js';
import { JsonlSink } from './adapters/sink/jsonl-sink.js';

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
  const monitor = buildMonitor({ policy, registerUrl: REGISTER_URL });
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
    protectedPaths: [sinkPath],
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
