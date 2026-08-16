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
export type Technique =
  | 'cloud-metadata'
  | 'dead-drop-c2'
  | 'ci-workflow-persistence'
  | 'git-hook-persistence'
  | 'editor-hook-persistence'
  | 'registry-publish';

/** One-line, plain-English gloss + what to check — shown next to the finding. */
export const TECHNIQUE_GLOSS: Record<Technique, string> = {
  'cloud-metadata':
    'cloud instance-metadata endpoint — the way CI/cloud credentials are stolen; no npm package should fetch instance credentials',
  'dead-drop-c2':
    'connecting to a public dead-drop / relay — a paste site, chat webhook, IPFS gateway, or blockchain RPC — used to fetch C2 config or exfiltrate without a fixed attacker domain (the keyv/ChainDrop worm read its C2 from an Ethereum transaction); legitimate for some apps, so allowlist the ones yours needs',
  'ci-workflow-persistence':
    'writing a CI/CD pipeline definition — the self-persistence move of the Shai-Hulud worm; nothing legitimate writes .github/workflows, .gitlab-ci.yml, Jenkinsfile & co. from inside a dependency',
  'git-hook-persistence':
    'writing a git hook (.git/hooks or .husky) — a payload here re-runs on every commit/checkout/push; nothing legitimate installs one from inside a dependency',
  'editor-hook-persistence':
    'writing an editor/AI-agent hook that auto-runs when the repo is opened (.vscode/tasks.json runOn:folderOpen, .claude/settings.json hooks, .devcontainer postCreateCommand, .envrc) — the keyv/ChainDrop worm’s move; nothing legitimate installs one from inside a dependency',
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
  '169.254.170.2', // AWS ECS task metadata / container credentials
  '169.254.170.23', // AWS EKS Pod Identity credentials
  '169.254.0.23', // Tencent Cloud CVM metadata
  '100.100.100.200', // Alibaba Cloud
  'fd00:ec2::254', // AWS IMDS over IPv6
]);

const METADATA_HOSTS: ReadonlySet<string> = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'instance-data', // AWS VPC DNS alias for 169.254.169.254
  'instance-data.ec2.internal',
  'metadata.tencentyun.com', // Tencent Cloud
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

  // The `inet_aton` short forms: the last part absorbs the remaining bytes.
  // `a.b` → a is the top octet, b the low 24 bits; `a.b.c` → c the low 16 bits.
  // These are as much a metadata-SSRF disguise as the single-integer form, and
  // this function's contract is to catch every `inet_aton` spelling.
  if (parts.length === 2) {
    const a = toNum(parts[0] ?? '');
    const rest = toNum(parts[1] ?? '');
    if (
      a !== null &&
      rest !== null &&
      a >= 0 &&
      a <= 255 &&
      rest >= 0 &&
      rest <= 0xffffff
    ) {
      return [a, (rest >>> 16) & 0xff, (rest >>> 8) & 0xff, rest & 0xff].join('.');
    }
    return h;
  }
  if (parts.length === 3) {
    const a = toNum(parts[0] ?? '');
    const b = toNum(parts[1] ?? '');
    const rest = toNum(parts[2] ?? '');
    if (
      a !== null &&
      b !== null &&
      rest !== null &&
      a >= 0 &&
      a <= 255 &&
      b >= 0 &&
      b <= 255 &&
      rest >= 0 &&
      rest <= 0xffff
    ) {
      return [a, b, (rest >>> 8) & 0xff, rest & 0xff].join('.');
    }
    return h;
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
  // Strip a trailing DNS root dot (`metadata.google.internal.` resolves to the
  // same name), then match by host and by canonicalised IP.
  const host = extractHost(detail).replace(/\.$/, '');
  if (METADATA_HOSTS.has(host)) return true;
  return METADATA_IPS.has(normalizeIpv4(host));
}

/**
 * Public "dead-drop" / relay channels a payload uses to fetch its C2 address or
 * exfiltrate without hard-coding an attacker domain — the move that let the
 * keyv/ChainDrop worm reconfigure its whole C2 from a single Ethereum
 * transaction. Matched by host suffix. Some are legitimate for certain apps
 * (a web3 project uses an RPC; a bot uses Telegram), so this names/surfaces the
 * connection rather than blocking on its own — the per-package allowlist decides.
 */
const DEAD_DROP_HOSTS: readonly string[] = [
  // Anonymous paste / file-drop services.
  'pastebin.com',
  'hastebin.com',
  'hasteb.in',
  'ghostbin.com',
  'dpaste.com',
  'dpaste.org',
  'ix.io',
  '0x0.st',
  'termbin.com',
  'transfer.sh',
  'rentry.co',
  'rentry.org',
  'paste.ee',
  'controlc.com',
  'clbin.com',
  'sprunge.us',
  'katb.in',
  // Chat / webhook exfil-and-C2 channels.
  'api.telegram.org',
  'discord.com',
  'discordapp.com',
  // IPFS gateways (content-addressed dead drops).
  'ipfs.io',
  'cloudflare-ipfs.com',
  'gateway.pinata.cloud',
  'dweb.link',
  'w3s.link',
  'nftstorage.link',
  // Blockchain RPC / explorers — the on-chain dead drop the keyv worm used.
  'infura.io',
  'alchemy.com',
  'alchemyapi.io',
  'etherscan.io',
  'cloudflare-eth.com',
  'ankr.com',
  'llamarpc.com',
  'publicnode.com',
  'drpc.org',
  '1rpc.io',
  'quicknode.com',
  'quiknode.pro',
  'blastapi.io',
  'blockpi.network',
  'nodereal.io',
];

/** True when an outbound target is a known public dead-drop / relay channel. */
export function isDeadDropHost(detail: string): boolean {
  const host = extractHost(detail).replace(/\.$/, '');
  return DEAD_DROP_HOSTS.some((h) => host === h || host.endsWith(`.${h}`));
}

/**
 * True when an IP address points *inside* the network — loopback, private (RFC
 * 1918), carrier-grade NAT, link-local (incl. cloud metadata), the unspecified
 * address, IPv6 loopback/link-local/ULA, and IPv4-mapped forms of all of those.
 *
 * This is the payoff of an SSRF redirect: an allowlisted *public* hostname that
 * resolves to one of these is reaching a service the dependency was never meant
 * to — the metadata endpoint, an internal admin API, a sidecar. Reused to bind
 * network enforcement to the *resolved* address, not the caller's hostname.
 */
export function isInternalTarget(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '');

  // IPv6 forms that are not an IPv4-mapped literal (those fall through to v4).
  if (h.includes(':') && !/(?:^|:)(?:\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    if (h === '::1' || h === '::') return true; // loopback / unspecified
    if (/^fe[89ab][0-9a-f]:/.test(h)) return true; // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true; // fc00::/7 unique-local (fc/fd)
    // else: a routable IPv6 — fall through (no v4 match) → not internal.
  }

  const v4 = normalizeIpv4(h);
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(v4);
  if (m === null) {
    return false;
  }
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 0 || // 0.0.0.0/8 unspecified
    a === 10 || // 10.0.0.0/8 private
    a === 127 || // 127.0.0.0/8 loopback
    (a === 169 && b === 254) || // 169.254.0.0/16 link-local (incl. metadata)
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 private
    (a === 192 && b === 168) || // 192.168.0.0/16 private
    (a === 100 && b >= 64 && b <= 127) // 100.64.0.0/10 carrier-grade NAT
  );
}

/**
 * Normalise a path for lexical persistence matching: `\` → `/`, then strip
 * trailing spaces and dots from every segment before lowercasing. Windows
 * silently drops trailing dots/spaces from filenames, so `ci.yml ` and `ci.yml.`
 * open the same file as `ci.yml` — without this a one-character suffix would
 * dodge the `$`-anchored patterns below.
 */
function normalizeForPersistence(path: string): string {
  return path
    .replace(/\\/g, '/')
    .replace(/[ .]+(?=\/|$)/g, '')
    .toLowerCase();
}

/**
 * Repo-root, single-file CI/CD pipeline definitions, matched by basename. Every
 * one of these auto-runs on the CI host when the repo is pushed, so planting or
 * rewriting one from inside a dependency is a self-persistence + re-exfiltration
 * move — symmetric to the Shai-Hulud `.github/workflows` plant, just on a
 * different provider. Matched anywhere in the tree (consistent with the workflow
 * dir rule) because the attack is the write itself.
 */
const CI_ROOT_BASENAMES: ReadonlySet<string> = new Set([
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  'azure-pipelines.yml',
  'azure-pipelines.yaml',
  '.travis.yml',
  'bitbucket-pipelines.yml',
  '.drone.yml',
  'appveyor.yml',
  'appveyor.yaml',
  '.appveyor.yml',
  '.cirrus.yml',
  'jenkinsfile',
]);

/** Dot-dir CI configs: CircleCI, Buildkite, Woodpecker. */
const CI_DOTDIR_CONFIG =
  /(^|\/)(\.circleci\/config|\.buildkite\/[^/]+|\.woodpecker(\/[^/]+)?)\.ya?ml$/;

/**
 * True when a write targets a CI/CD pipeline definition. Covers GitHub Actions
 * and the compatible forges (Gitea, Forgejo), local/composite GitHub Action
 * manifests (`.github/actions/<x>/action.yml` — overwriting one plants CI-run
 * code), the dot-dir configs (CircleCI/Buildkite/Woodpecker), and the
 * single-file pipeline definitions of the other major providers. Writing any of
 * them during an install/build is the worm's persistence step; nothing
 * legitimate does it from inside a dependency.
 */
export function isCiWorkflowPath(path: string): boolean {
  const p = normalizeForPersistence(path);
  if (
    // GitHub / Gitea / Forgejo workflow directories.
    /(^|\/)\.(github|gitea|forgejo)\/workflows\/[^/]+\.ya?ml$/.test(p) ||
    // Local / composite GitHub Action manifests.
    /(^|\/)\.github\/actions\/[^/]+\/action\.ya?ml$/.test(p) ||
    CI_DOTDIR_CONFIG.test(p)
  ) {
    return true;
  }
  const name = p.slice(p.lastIndexOf('/') + 1);
  return CI_ROOT_BASENAMES.has(name);
}

/**
 * The git hook names git will actually execute (the `.sample` templates git
 * ships are inert and excluded). A hook is an arbitrary executable that runs on
 * a git event, so a payload dropped here re-runs on every commit/checkout/push —
 * classic local persistence.
 */
const GIT_HOOK_NAMES: ReadonlySet<string> = new Set([
  'applypatch-msg',
  'pre-applypatch',
  'post-applypatch',
  'pre-commit',
  'pre-merge-commit',
  'prepare-commit-msg',
  'commit-msg',
  'post-commit',
  'pre-rebase',
  'post-checkout',
  'post-merge',
  'pre-push',
  'post-rewrite',
  'pre-receive',
  'update',
  'post-receive',
  'post-update',
  'push-to-checkout',
  'pre-auto-gc',
  'post-index-change',
  'sendemail-validate',
]);

/**
 * True when a write targets a git hook — under `.git/hooks/` (git's own hook
 * dir) or `.husky/` (the Husky manager's committed hooks). Restricted to the
 * names git actually runs so Husky's own internals (`.husky/_/husky.sh`) and
 * arbitrary files do not trip it. Only a dependency dropping one is flagged;
 * the user wiring up their own hooks is application-origin and always allowed.
 */
export function isGitHookPath(path: string): boolean {
  const p = normalizeForPersistence(path);
  const m = /(^|\/)(\.git\/hooks|\.husky)\/([^/]+)$/.exec(p);
  if (m === null) {
    return false;
  }
  return GIT_HOOK_NAMES.has(m[3] ?? '');
}

/**
 * Editor / AI-agent hook files that auto-run a command when the repository is
 * opened, matched on the normalised (backslash → `/`, trailing-junk-stripped,
 * lowercased) path. This is the persistence move of the 2026 keyv/ChainDrop worm,
 * which planted a `.vscode/tasks.json` (`runOn: folderOpen`) and a
 * `.claude/settings.json` `SessionStart` hook that ran its loader the moment a
 * developer opened the checked-out repo. Nothing legitimate writes any of these
 * from inside a dependency — the developer authors them, which is
 * application-origin and always allowed.
 */
const EDITOR_HOOK_PATTERNS: readonly RegExp[] = [
  // VS Code: tasks.json auto-runs (runOn: folderOpen); settings.json can point a
  // tool path (git.path, eslint.runtime, python.defaultInterpreterPath, …) at a
  // dropped binary; launch.json runs on debug.
  /(^|\/)\.vscode\/(tasks|settings|launch)\.json$/,
  // A VS Code multi-root workspace file carries the same settings/tasks inline.
  /(^|\/)[^/]+\.code-workspace$/,
  // Claude Code hooks (SessionStart/PreToolUse/… run shell commands).
  /(^|\/)\.claude\/settings(\.local)?\.json$/,
  /(^|\/)\.claude\/hooks\/[^/]+$/,
  // Cursor / Windsurf launch an MCP server command from their config.
  /(^|\/)\.cursor\/mcp\.json$/,
  /(^|\/)\.windsurf\/mcp\.json$/,
  // Dev containers run lifecycle commands (postCreateCommand / initializeCommand,
  // the latter on the host) when the container/Codespace opens.
  /(^|\/)\.devcontainer\/([^/]+\/)?devcontainer\.json$/,
  // JetBrains run configurations.
  /(^|\/)\.idea\/runconfigurations\/[^/]+\.xml$/,
  // direnv executes .envrc on cd into the directory.
  /(^|\/)\.envrc$/,
];

/** True when a write targets an editor/AI-agent hook that auto-runs on open. */
export function isEditorHookPath(path: string): boolean {
  const p = normalizeForPersistence(path);
  return EDITOR_HOOK_PATTERNS.some((pattern) => pattern.test(p));
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
      if (isCloudMetadataHost(detail)) return 'cloud-metadata';
      if (isDeadDropHost(detail)) return 'dead-drop-c2';
      return null;
    case 'fs.write':
      if (isCiWorkflowPath(detail)) return 'ci-workflow-persistence';
      if (isGitHookPath(detail)) return 'git-hook-persistence';
      if (isEditorHookPath(detail)) return 'editor-hook-persistence';
      return null;
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
