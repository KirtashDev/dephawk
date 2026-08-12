/**
 * Named, high-signal attack-technique detection — the durable invariants of real
 * npm supply-chain worms (Shai-Hulud, ChainDrop, the axios RAT).
 *
 * These are *not* a threat feed of rotating indicators (attacker domains change
 * hourly; a runtime tripwire that chases them has become a worse antivirus). They
 * are the moves that never change and never fire legitimately at install time:
 * fetching cloud instance credentials, planting a CI workflow, self-publishing to
 * the registry. Each is already blocked at the leaf by the capability model — the
 * value here is *naming* the technique so a report reads "cloud-metadata SSRF"
 * instead of "connect 169.254.169.254", and marking it sensitive so it surfaces
 * even in observe mode.
 *
 * Pure: string/number transforms only, no Node types, trivially testable.
 */
import type { Capability } from './capability.js';
import type { DhEvent } from './event.js';
import { extractHost } from './host.js';

/** A recognised attack technique. */
export type Technique = 'cloud-metadata' | 'ci-workflow-persistence' | 'registry-publish';

/** One-line, plain-English gloss + what to check — shown next to the finding. */
export const TECHNIQUE_GLOSS: Record<Technique, string> = {
  'cloud-metadata':
    'cloud instance-metadata endpoint — the way CI/cloud credentials are stolen; no npm package should fetch instance credentials',
  'ci-workflow-persistence':
    'writing a CI workflow — the self-persistence move of the Shai-Hulud worm; nothing legitimate writes .github/workflows during an install',
  'registry-publish':
    'publishing to the package registry — how a worm self-replicates with a stolen token',
};

/**
 * The canonical cloud instance-metadata endpoints. Link-local by design (RFC
 * 3927 / 6890), so a dependency reaching one during an install is fetching
 * ephemeral cloud credentials — the single sharpest supply-chain signal.
 */
const METADATA_IPS: ReadonlySet<string> = new Set([
  '169.254.169.254', // AWS IMDS, Azure IMDS, GCP, DigitalOcean, Oracle
  '169.254.170.2', // AWS ECS/EKS task metadata
  '100.100.100.200', // Alibaba Cloud
  'fd00:ec2::254', // AWS IMDS over IPv6
]);

const METADATA_HOSTS: ReadonlySet<string> = new Set([
  'metadata.google.internal',
  'metadata.goog',
]);

/**
 * Normalise an IPv4 host written in a non-dotted-decimal form to `a.b.c.d`, so
 * decimal (`2852039166`), hex (`0xA9FEA9FE`), octal, mixed-radix dotted, and
 * IPv4-mapped IPv6 (`::ffff:169.254.169.254`) spellings of a metadata address
 * cannot dodge the match. Returns the input unchanged when it is not an integer
 * IPv4 form. This is dephawk's classic bypass class — the same reason paths are
 * canonicalised — so it is handled up front.
 */
export function normalizeIpv4(host: string): string {
  const h = host.trim().toLowerCase();

  // IPv4-mapped / -compatible IPv6: take the trailing IPv4-looking part.
  const mapped = /(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(h);
  if (mapped?.[1]) {
    return mapped[1];
  }

  const parts = h.split('.');
  const toNum = (p: string): number | null => {
    if (p === '') return null;
    let n: number;
    if (/^0x[0-9a-f]+$/.test(p)) n = parseInt(p.slice(2), 16);
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p.slice(1), 8);
    else if (/^\d+$/.test(p)) n = parseInt(p, 10);
    else return null;
    return Number.isSafeInteger(n) ? n : null;
  };

  // A single integer (decimal/hex/octal) is a 32-bit IPv4.
  if (parts.length === 1) {
    const n = toNum(parts[0] ?? '');
    if (n === null || n < 0 || n > 0xffffffff) return h;
    return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
  }

  // Dotted quad with possibly hex/octal octets.
  if (parts.length === 4) {
    const octets = parts.map(toNum);
    if (octets.every((o) => o !== null && o >= 0 && o <= 255)) {
      return octets.join('.');
    }
  }
  return h;
}

/** True when an outbound target is a cloud instance-metadata endpoint. */
export function isCloudMetadataHost(detail: string): boolean {
  const host = extractHost(detail);
  if (METADATA_HOSTS.has(host)) return true;
  return METADATA_IPS.has(normalizeIpv4(host));
}

/**
 * True when a write targets a CI workflow definition — `.github/workflows/`.
 * Writing one during an install/build is the worm's persistence step (a
 * scheduled action that re-runs the payload and re-exfiltrates on every push);
 * nothing legitimate does it from inside a dependency.
 */
export function isCiWorkflowPath(path: string): boolean {
  const p = path.replace(/\\/g, '/').toLowerCase();
  return /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(p);
}

/** True when a spawned command publishes to a package registry. */
export function isRegistryPublish(command: string): boolean {
  // `npm publish`, `pnpm publish`, `yarn publish`, `npm exec -- … publish` — the
  // package-manager binary followed by a `publish` verb somewhere in the argv.
  const c = command.toLowerCase();
  return (
    /(^|[\s/])(npm|pnpm|yarn|bun|npx)([\s/]|\.\w+\s|\s)/.test(c) && /\bpublish\b/.test(c)
  );
}

/**
 * The attack technique a capability request matches, or null. Pure function of
 * the capability and its detail, so both the policy engine (to mark the request
 * sensitive) and the reporters (to name it) derive it the same way.
 */
export function detectTechnique(
  capability: Capability,
  detail: string,
): Technique | null {
  switch (capability) {
    case 'net.connect':
    case 'net.resolve':
      return isCloudMetadataHost(detail) ? 'cloud-metadata' : null;
    case 'fs.write':
      return isCiWorkflowPath(detail) ? 'ci-workflow-persistence' : null;
    case 'process.spawn':
      return isRegistryPublish(detail) ? 'registry-publish' : null;
    default:
      return null;
  }
}

/** One dependency's read-a-secret-then-reach-the-network chain. */
export interface ExfilChain {
  /** The dependency responsible. */
  readonly package: string;
  /** Detail of the secret it read (path or env var name). */
  readonly secret: string;
  /** Detail of the outbound sink it then reached. */
  readonly sink: string;
}

/**
 * The behavioural signature every credential-stealer shares, whatever the sink:
 * the same dependency **reads a secret and then reaches the network**. This is
 * host-agnostic (no rotating blocklist) and campaign-agnostic (Shai-Hulud,
 * ChainDrop, the axios RAT all do it), and it is derived from the *causal order*
 * of attributed events already recorded — not a timer, which would flake in CI.
 *
 * A chain is: a sensitive `fs.read`/`env.read` by a dependency, followed later in
 * the event stream by a `net.connect`/`net.resolve` by that same dependency. Each
 * package is reported once (its first such egress). Observe-only signal — it
 * annotates the report; it never blocks (the individual leaves are already gated
 * on their own). dephawk's secret set is narrow (`~/.ssh`, `.npmrc`, cloud creds,
 * secret-shaped env), so a dependency hitting one and then phoning home is a
 * high-signal, low-false-positive pattern.
 */
export function detectExfilChains(events: readonly DhEvent[]): ExfilChain[] {
  const chains: ExfilChain[] = [];
  const firstSecretRead = new Map<string, string>();
  const reported = new Set<string>();

  for (const event of events) {
    if (event.origin !== 'dependency' || event.package === null) {
      continue;
    }
    const pkg = event.package;
    const readSecret =
      (event.capability === 'fs.read' || event.capability === 'env.read') &&
      event.sensitive;
    const reachedNetwork =
      event.capability === 'net.connect' || event.capability === 'net.resolve';

    if (readSecret && !firstSecretRead.has(pkg)) {
      firstSecretRead.set(pkg, event.detail);
    } else if (reachedNetwork && firstSecretRead.has(pkg) && !reported.has(pkg)) {
      reported.add(pkg);
      chains.push({
        package: pkg,
        secret: firstSecretRead.get(pkg) ?? '',
        sink: event.detail,
      });
    }
  }
  return chains;
}
