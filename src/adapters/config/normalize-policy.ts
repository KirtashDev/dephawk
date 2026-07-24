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
 * Anything malformed is dropped rather than trusted. Pure and fully tested,
 * which is why it lives apart from the loaders that do the I/O.
 */
export function normalizePolicy(input: unknown): Policy {
  if (!isRecord(input)) {
    return PERMISSIVE_POLICY;
  }

  const packages: Record<string, PackagePolicy> = {};
  const packagesInput = input['packages'];
  if (isRecord(packagesInput)) {
    for (const [name, value] of Object.entries(packagesInput)) {
      packages[name] = normalizePackagePolicy(value);
    }
  }

  return {
    mode: normalizeMode(input['mode']) ?? PERMISSIVE_POLICY.mode,
    default: normalizePackagePolicy(input['default']),
    packages,
  };
}

/** Apply a `DEPHAWK_MODE`-style override string, if it is a valid mode. */
export function applyModeOverride(policy: Policy, mode: string | undefined): Policy {
  const normalised = normalizeMode(mode);
  return normalised === undefined ? policy : { ...policy, mode: normalised };
}

function normalizePackagePolicy(input: unknown): PackagePolicy {
  if (!isRecord(input)) {
    return {};
  }
  const policy: {
    net?: NetPolicy;
    fs?: FsPolicy;
    spawn?: boolean;
    env?: EnvPolicy;
  } = {};

  const net = normalizeNet(input['net']);
  if (net !== undefined) {
    policy.net = net;
  }
  const fs = normalizeFs(input['fs']);
  if (fs !== undefined) {
    policy.fs = fs;
  }
  if (typeof input['spawn'] === 'boolean') {
    policy.spawn = input['spawn'];
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
  const connect = asStringArray(input['connect']);
  return connect === undefined ? {} : { connect };
}

function normalizeFs(input: unknown): FsPolicy | undefined {
  if (!isRecord(input)) {
    return undefined;
  }
  const read = asStringArray(input['read']);
  const write = asStringArray(input['write']);
  const fs: { read?: readonly string[]; write?: readonly string[] } = {};
  if (read !== undefined) {
    fs.read = read;
  }
  if (write !== undefined) {
    fs.write = write;
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
