import { resolveEnvPolicy } from './adapters/config/policy-loader.js';
import { buildMonitor } from './composition/build-monitor.js';

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

  // Normal completion: the event loop drains, we write the report, then exit.
  process.once('beforeExit', () => {
    void finish();
  });

  // Ctrl-C / termination: report, then exit with the conventional code.
  const onSignal = (code: number): void => {
    void finish().finally(() => process.exit(code));
  };
  process.once('SIGINT', () => onSignal(130));
  process.once('SIGTERM', () => onSignal(143));
}
