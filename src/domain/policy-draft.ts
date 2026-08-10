import type { Capability } from './capability.js';
import type { DhEvent } from './event.js';
import { extractHost } from './host.js';
import type { PackagePolicy, Policy } from './policy.js';

/**
 * Turning an observed run into a starting policy.
 *
 * Writing a policy by hand is the thing that stops people turning `--enforce`
 * (or `--fail-on violation`) on: a real project has dependencies that
 * legitimately reach the network, shell out, and read `.npmrc`, and every one
 * of them has to be allowlisted before the first green run. So dephawk watches
 * a run and drafts the allowlist that would have made it pass.
 *
 * **This grants whatever it saw.** If something malicious is already in the
 * tree, drafting from a run permits its exfiltration as readily as it permits
 * your HTTP client's API calls — dephawk cannot tell intent from behaviour. The
 * draft is a starting point for review, and every entry carries a note saying
 * what produced it so that review is possible. {@link PackageNote.needsReview}
 * marks the grants that hand over general-purpose power and should not be
 * accepted without knowing why the package wants them.
 */

/** What was observed for one package, so a human can judge the draft. */
export interface PackageNote {
  readonly package: string;
  /** One line per distinct thing the package did. */
  readonly observations: readonly string[];
  /** Capabilities granted here that deserve a hard look. */
  readonly needsReview: readonly Capability[];
}

export interface PolicyDraft {
  readonly policy: Policy;
  readonly notes: readonly PackageNote[];
  /**
   * Findings dephawk could not pin on a package. Never drafted into a rule:
   * the only place to put them is the default bucket, which would weaken it for
   * every package at once.
   */
  readonly unattributed: readonly string[];
}

export interface DraftOptions {
  /** Home directory, rewritten to `~` so the draft is portable. */
  readonly homeDir?: string;
}

/**
 * Capabilities that grant open-ended power rather than access to one named
 * thing. A host allowlist is bounded; `spawn: true` is not.
 */
const NEEDS_REVIEW: readonly Capability[] = [
  'process.spawn',
  'process.native',
  'code.eval',
  'net.listen',
];

interface Grants {
  hosts: Set<string>;
  envVars: Set<string>;
  reads: Set<string>;
  writes: Set<string>;
  spawn: boolean;
  native: boolean;
  evaluate: boolean;
  listen: boolean;
  observations: Set<string>;
  reviewable: Set<Capability>;
}

/**
 * Draft the policy that would have permitted everything in `events`.
 *
 * Only denials are drafted — those are exactly the calls that would fail a run
 * — and only where they were attributed to a dependency.
 */
export function draftPolicy(
  events: readonly DhEvent[],
  options: DraftOptions = {},
): PolicyDraft {
  const home = options.homeDir ?? '';
  const byPackage = new Map<string, Grants>();
  const unattributed = new Set<string>();

  for (const event of events) {
    if (event.allowed) {
      continue;
    }
    if (event.package === null) {
      unattributed.add(`${event.capability} ${shorten(event.detail, home)}`);
      continue;
    }
    record(grantsFor(byPackage, event.package), event, home);
  }

  const packages: Record<string, PackagePolicy> = {};
  const notes: PackageNote[] = [];

  for (const name of [...byPackage.keys()].sort()) {
    const grants = byPackage.get(name)!;
    packages[name] = toPackagePolicy(grants);
    notes.push({
      package: name,
      observations: [...grants.observations].sort(),
      needsReview: NEEDS_REVIEW.filter((capability) => grants.reviewable.has(capability)),
    });
  }

  return {
    policy: {
      mode: 'observe',
      // Left deny-by-default on purpose: the draft's value is that everything
      // not seen stays refused, including calls dephawk could not attribute.
      default: { net: { connect: [] }, spawn: false, env: false },
      packages,
    },
    notes,
    unattributed: [...unattributed].sort(),
  };
}

function grantsFor(byPackage: Map<string, Grants>, name: string): Grants {
  const existing = byPackage.get(name);
  if (existing !== undefined) {
    return existing;
  }
  const created: Grants = {
    hosts: new Set(),
    envVars: new Set(),
    reads: new Set(),
    writes: new Set(),
    spawn: false,
    native: false,
    evaluate: false,
    listen: false,
    observations: new Set(),
    reviewable: new Set(),
  };
  byPackage.set(name, created);
  return created;
}

function record(grants: Grants, event: DhEvent, home: string): void {
  const detail = shorten(event.detail, home);

  switch (event.capability) {
    case 'net.connect':
    case 'net.resolve': {
      const host = extractHost(event.detail);
      grants.hosts.add(host);
      grants.observations.add(`connected to ${host}`);
      break;
    }
    case 'net.listen':
      grants.listen = true;
      grants.reviewable.add('net.listen');
      grants.observations.add(`opened an inbound listener (${detail})`);
      break;
    case 'env.read':
      grants.envVars.add(event.detail);
      grants.observations.add(`read the secret ${event.detail}`);
      break;
    case 'fs.read':
      grants.reads.add(detail);
      grants.observations.add(`read ${detail}`);
      break;
    case 'fs.write':
      grants.writes.add(detail);
      grants.observations.add(`wrote ${detail}`);
      break;
    case 'process.spawn':
      grants.spawn = true;
      grants.reviewable.add('process.spawn');
      grants.observations.add(`spawned ${detail}`);
      break;
    case 'process.native':
      grants.native = true;
      grants.reviewable.add('process.native');
      grants.observations.add(`loaded the native addon ${detail}`);
      break;
    case 'code.eval':
      grants.evaluate = true;
      grants.reviewable.add('code.eval');
      grants.observations.add('executed dynamically compiled code');
      break;
    case 'os.info':
      // Never denied, so it never needs a rule.
      break;
  }
}

function toPackagePolicy(grants: Grants): PackagePolicy {
  const policy: {
    net?: { connect?: readonly string[]; listen?: boolean };
    fs?: { read?: readonly string[]; write?: readonly string[] };
    spawn?: boolean;
    native?: boolean;
    eval?: boolean;
    env?: readonly string[];
  } = {};

  if (grants.hosts.size > 0 || grants.listen) {
    policy.net = {
      ...(grants.hosts.size > 0 ? { connect: sorted(grants.hosts) } : {}),
      ...(grants.listen ? { listen: true } : {}),
    };
  }
  if (grants.reads.size > 0 || grants.writes.size > 0) {
    policy.fs = {
      ...(grants.reads.size > 0 ? { read: sorted(grants.reads) } : {}),
      ...(grants.writes.size > 0 ? { write: sorted(grants.writes) } : {}),
    };
  }
  if (grants.spawn) {
    policy.spawn = true;
  }
  if (grants.native) {
    policy.native = true;
  }
  if (grants.evaluate) {
    policy.eval = true;
  }
  if (grants.envVars.size > 0) {
    policy.env = sorted(grants.envVars);
  }
  return policy;
}

function sorted(values: ReadonlySet<string>): readonly string[] {
  return [...values].sort();
}

/** Rewrite the home directory back to `~` so the draft travels. */
function shorten(detail: string, home: string): string {
  if (home.length === 0) {
    return detail;
  }
  const prefix = home.endsWith('/') ? home : `${home}/`;
  return detail.startsWith(prefix) ? `~/${detail.slice(prefix.length)}` : detail;
}
