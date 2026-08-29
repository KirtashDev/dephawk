/**
 * The sensitive runtime capabilities dephawk knows how to observe.
 *
 * This is domain vocabulary: it never references Node types. Adapters translate
 * concrete built-in calls (`fs.readFileSync`, `net.connect`, …) into one of
 * these capabilities before handing them to the application layer.
 */
export const CAPABILITIES = [
  'fs.read',
  'fs.write',
  'net.connect',
  'net.resolve',
  'net.listen',
  'process.spawn',
  'process.native',
  'code.eval',
  'process.memory',
  'env.read',
  'env.write',
  'os.info',
] as const;

export type Capability = (typeof CAPABILITIES)[number];

export interface CapabilityMeta {
  /** Short human label, used by reporters. */
  readonly label: string;
  /** One-line description of what the capability represents. */
  readonly description: string;
  /**
   * Whether the *detail* of a request under this capability can itself be
   * sensitive (a secret path, a secret env var). `net.connect` and `os.info`
   * derive their signal from policy, not from intrinsic sensitivity.
   */
  readonly detailCanBeSensitive: boolean;
}

export const CAPABILITY_META: Readonly<Record<Capability, CapabilityMeta>> = {
  'fs.read': {
    label: 'read',
    description: 'Read a file from disk.',
    detailCanBeSensitive: true,
  },
  'fs.write': {
    label: 'write',
    description: 'Write or modify a file on disk.',
    detailCanBeSensitive: true,
  },
  'net.connect': {
    label: 'connect',
    description: 'Open an outbound network connection or HTTP request.',
    detailCanBeSensitive: false,
  },
  'net.resolve': {
    label: 'dns',
    description: 'Resolve a hostname via DNS (a connection precursor or exfil channel).',
    detailCanBeSensitive: false,
  },
  'net.listen': {
    label: 'listen',
    description: 'Open an inbound listener/bind (a backdoor or C2 channel).',
    detailCanBeSensitive: false,
  },
  'process.spawn': {
    label: 'spawn',
    description: 'Spawn a child process or shell.',
    detailCanBeSensitive: false,
  },
  'process.native': {
    label: 'native',
    description: 'Load a native addon (.node) via process.dlopen.',
    detailCanBeSensitive: false,
  },
  'code.eval': {
    label: 'eval',
    description: 'Execute dynamically compiled code via the vm module.',
    detailCanBeSensitive: false,
  },
  'process.memory': {
    label: 'memory',
    description:
      'Dump the process memory or full environment (heap snapshot, diagnostic report).',
    detailCanBeSensitive: false,
  },
  'env.read': {
    label: 'env',
    description: 'Read an environment variable.',
    detailCanBeSensitive: true,
  },
  'env.write': {
    label: 'env set',
    description:
      'Write, overwrite or delete a security-relevant environment variable (TLS verification, NODE_OPTIONS, dephawk’s own settings).',
    detailCanBeSensitive: false,
  },
  'os.info': {
    label: 'os',
    description: 'Read host/OS information (user, network interfaces).',
    detailCanBeSensitive: false,
  },
};

export function isCapability(value: string): value is Capability {
  return (CAPABILITIES as readonly string[]).includes(value);
}

/**
 * The variable name out of an `env.write` detail.
 *
 * That detail carries the *value* — `NODE_TLS_REJECT_UNAUTHORIZED=0`, or
 * `NODE_OPTIONS (deleted)` for a removal — because what a guarded variable was
 * set to is the whole finding: `=0` disables certificate validation
 * process-wide, `=1` restores it, and a report that showed only the name could
 * not tell them apart. Every consumer that needs the bare name (the policy
 * allowlist, the drafted config) derives it here rather than re-parsing.
 */
export function envWriteName(detail: string): string {
  return /^[^=\s]*/.exec(detail)?.[0] ?? detail;
}
