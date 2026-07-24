import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { PERMISSIVE_POLICY, type Policy } from '../../domain/policy.js';
import type { PolicyLoader } from '../../application/ports.js';
import { applyModeOverride, normalizePolicy } from './normalize-policy.js';

type Env = Record<string, string | undefined>;

/**
 * The env-JSON loader used by the `--import` entrypoint.
 *
 * The CLI resolves the (possibly async ESM) config file *before* spawning the
 * child and passes the already-resolved policy as JSON in `DEPHAWK_POLICY`.
 * This keeps `register.ts` free of async config resolution — the crux of
 * requirement #5. `DEPHAWK_MODE` still overrides the mode last.
 */
export class EnvPolicyLoader implements PolicyLoader {
  private readonly env: Env;

  constructor(env: Env = process.env) {
    this.env = env;
  }

  load(): Promise<Policy> {
    return Promise.resolve(this.resolve());
  }

  private resolve(): Policy {
    const json = this.env['DEPHAWK_POLICY'];
    let policy = PERMISSIVE_POLICY;
    if (json !== undefined && json.length > 0) {
      policy = safeParse(json);
    }
    return applyModeOverride(policy, this.env['DEPHAWK_MODE']);
  }
}

export type ConfigImporter = (specifier: string) => Promise<unknown>;

export interface FileConfigPolicyLoaderOptions {
  /** Absolute or cwd-relative path to the config module, or null for none. */
  readonly configPath: string | null;
  readonly env?: Env;
  /** Injectable importer (defaults to dynamic `import()`), for testability. */
  readonly importer?: ConfigImporter;
  /** Sink for load warnings; defaults to stderr. */
  readonly warn?: (message: string) => void;
}

/**
 * The async loader used by the CLI. Dynamically imports the config module,
 * takes its default export, and normalises it. Failures degrade to the
 * permissive policy with a warning — a broken config must never crash the run.
 */
export class FileConfigPolicyLoader implements PolicyLoader {
  private readonly configPath: string | null;
  private readonly env: Env;
  private readonly importer: ConfigImporter;
  private readonly warn: (message: string) => void;

  constructor(options: FileConfigPolicyLoaderOptions) {
    this.configPath = options.configPath;
    this.env = options.env ?? process.env;
    this.importer = options.importer ?? defaultImporter;
    this.warn = options.warn ?? ((message) => process.stderr.write(`${message}\n`));
  }

  async load(): Promise<Policy> {
    let policy = PERMISSIVE_POLICY;
    if (this.configPath !== null) {
      try {
        const module = await this.importer(this.configPath);
        policy = normalizePolicy(extractConfig(module));
      } catch (error) {
        this.warn(
          `dephawk: failed to load config from ${this.configPath}: ${describe(error)}`,
        );
        policy = PERMISSIVE_POLICY;
      }
    }
    return applyModeOverride(policy, this.env['DEPHAWK_MODE']);
  }
}

function defaultImporter(specifier: string): Promise<unknown> {
  return import(pathToFileURL(resolve(specifier)).href);
}

/** Accept both `export default {...}` and `module.exports = {...}` shapes. */
function extractConfig(module: unknown): unknown {
  if (typeof module === 'object' && module !== null && 'default' in module) {
    return (module as { default: unknown }).default;
  }
  return module;
}

function safeParse(json: string): Policy {
  try {
    return normalizePolicy(JSON.parse(json));
  } catch {
    return PERMISSIVE_POLICY;
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
