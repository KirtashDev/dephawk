import { loadBuiltin } from '../interceptors/support.js';

const { homedir } = loadBuiltin('node:os') as { homedir: () => string };
import {
  PERMISSIVE_POLICY,
  type EnvPolicy,
  type FsPolicy,
  type Mode,
  type NetPolicy,
  type PackagePolicy,
  type Policy,
} from '../../domain/policy.js';

/**
 * Defensive normalisation of untrusted config into a valid {@link Policy}.
 *
 * Config comes from a user-authored file or a JSON env var, so it is `unknown`.
 * Anything malformed is dropped rather than trusted.
 *
 * Filesystem patterns may start with `~/`, which is expanded here. A config is
 * meant to be committed and run on other people's machines and in CI, and
 * `/Users/alice/.npmrc` is true in exactly one of those places — so the
 * portable spelling has to work, or every generated config would be
 * machine-specific.
 */
export interface NormalizeOptions {
  /** Home directory `~/` expands to. Defaults to the current user's. */
  readonly homeDir?: string;
}

export function normalizePolicy(input: unknown, options: NormalizeOptions = {}): Policy {
  if (!isRecord(input)) {
    return PERMISSIVE_POLICY;
  }

  const home = options.homeDir ?? safeHomeDir();

  const packages: Record<string, PackagePolicy> = {};
  const packagesInput = input['packages'];
  if (isRecord(packagesInput)) {
    for (const [name, value] of Object.entries(packagesInput)) {
      packages[name] = normalizePackagePolicy(value, home);
    }
  }

  return {
    mode: normalizeMode(input['mode']) ?? PERMISSIVE_POLICY.mode,
    default: normalizePackagePolicy(input['default'], home),
    packages,
  };
}

/** Replace a leading `~/` with the home directory. */
export function expandHome(pattern: string, home: string): string {
  if (pattern === '~') {
    return home;
  }
  return pattern.startsWith('~/') ? `${home}/${pattern.slice(2)}` : pattern;
}

function safeHomeDir(): string {
  try {
    return homedir();
  } catch {
    return '';
  }
}

/** Apply a `DEPHAWK_MODE`-style override string, if it is a valid mode. */
export function applyModeOverride(policy: Policy, mode: string | undefined): Policy {
  const normalised = normalizeMode(mode);
  return normalised === undefined ? policy : { ...policy, mode: normalised };
}

function normalizePackagePolicy(input: unknown, home: string): PackagePolicy {
  if (!isRecord(input)) {
    return {};
  }
  const policy: {
    net?: NetPolicy;
    fs?: FsPolicy;
    spawn?: boolean;
    native?: boolean;
    eval?: boolean;
    env?: EnvPolicy;
  } = {};

  const net = normalizeNet(input['net']);
  if (net !== undefined) {
    policy.net = net;
  }
  const fs = normalizeFs(input['fs'], home);
  if (fs !== undefined) {
    policy.fs = fs;
  }
  if (typeof input['spawn'] === 'boolean') {
    policy.spawn = input['spawn'];
  }
  if (typeof input['native'] === 'boolean') {
    policy.native = input['native'];
  }
  if (typeof input['eval'] === 'boolean') {
    policy.eval = input['eval'];
  }
  const env = normalizeEnv(input['env']);
  if (env !== undefined) {
    policy.env = env;
  }
  return policy;
}

function normalizeNet(input: unknown): NetPolicy | undefined {
  if (!isRecord(input)) {
    return undefined;
  }
  const net: { connect?: readonly string[]; listen?: boolean } = {};
  const connect = asStringArray(input['connect']);
  if (connect !== undefined) {
    net.connect = connect;
  }
  if (typeof input['listen'] === 'boolean') {
    net.listen = input['listen'];
  }
  return net;
}

function normalizeFs(input: unknown, home: string): FsPolicy | undefined {
  if (!isRecord(input)) {
    return undefined;
  }
  const expand = (patterns: readonly string[]): readonly string[] =>
    patterns.map((pattern) => expandHome(pattern, home));

  const read = asStringArray(input['read']);
  const write = asStringArray(input['write']);
  const fs: { read?: readonly string[]; write?: readonly string[] } = {};
  if (read !== undefined) {
    fs.read = expand(read);
  }
  if (write !== undefined) {
    fs.write = expand(write);
  }
  return fs;
}

function normalizeEnv(input: unknown): EnvPolicy | undefined {
  if (typeof input === 'boolean') {
    return input;
  }
  return asStringArray(input);
}

function normalizeMode(input: unknown): Mode | undefined {
  return input === 'observe' || input === 'enforce' ? input : undefined;
}

function asStringArray(input: unknown): readonly string[] | undefined {
  if (!Array.isArray(input)) {
    return undefined;
  }
  return input.filter((item): item is string => typeof item === 'string');
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}
