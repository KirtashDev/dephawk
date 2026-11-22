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
import type { Origin } from './origin.js';
import { extractHost, extractPort } from './host.js';
import { isAiCredentialPath } from './sensitivity.js';

/** A recognised attack technique. */
export type Technique =
  | 'cloud-metadata'
  | 'dead-drop-c2'
  | 'local-service-pivot'
  | 'ci-workflow-persistence'
  | 'git-hook-persistence'
  | 'editor-hook-persistence'
  | 'service-persistence'
  | 'manifest-tamper'
  | 'registry-publish'
  | 'alt-runtime-escape'
  | 'detached-process'
  | 'tls-verification-disabled'
  | 'ai-credential-theft'
  | 'destructive-wipe'
  | 'agent-instruction-tamper'
  | 'ci-oidc-token-theft';

/** One-line, plain-English gloss + what to check — shown next to the finding. */
export const TECHNIQUE_GLOSS: Record<Technique, string> = {
  'cloud-metadata':
    'cloud instance-metadata endpoint — the way CI/cloud credentials are stolen; no npm package should fetch instance credentials',
  'dead-drop-c2':
    'connecting to a public dead-drop / relay — a paste site, chat webhook, IPFS gateway, or blockchain RPC — used to fetch C2 config or exfiltrate without a fixed attacker domain (the keyv/ChainDrop worm read its C2 from an Ethereum transaction); legitimate for some apps, so allowlist the ones yours needs',
  'local-service-pivot':
    'connecting to infrastructure on the local network — a database, cache, container runtime or orchestrator port that is unauthenticated precisely because it is not meant to be reachable. The 36 hijacked Strapi packages probed a local Redis (INFO/DBSIZE/KEYS), injected a crontab through it, then went at PostgreSQL with hardcoded credentials; a reachable Docker or kubelet API is a straight container escape. Legitimate for an app that runs its own Redis or Postgres, so allowlist the ones yours needs',
  'ci-workflow-persistence':
    'writing a CI/CD pipeline definition — the self-persistence move of the Shai-Hulud worm; nothing legitimate writes .github/workflows, .gitlab-ci.yml, Jenkinsfile & co. from inside a dependency',
  'git-hook-persistence':
    'writing a git hook (.git/hooks or .husky) — a payload here re-runs on every commit/checkout/push; nothing legitimate installs one from inside a dependency',
  'editor-hook-persistence':
    'writing an editor/AI-agent hook that auto-runs when the repo is opened (.vscode/tasks.json runOn:folderOpen, .claude/settings.json hooks, .devcontainer postCreateCommand, .envrc) — the keyv/ChainDrop worm’s move; nothing legitimate installs one from inside a dependency',
  'service-persistence':
    'installing an OS-level autostart entry (systemd unit, launchd agent, cron job, Windows Run key/scheduled task, SSH authorized_keys) — persistence that survives the build, the shell and often credential rotation; nothing legitimate installs one from inside a dependency',
  'manifest-tamper':
    'rewriting an installed package’s package.json — how ChainDrop propagated: download the victim’s tarball, inject a preinstall hook, bump the patch version, republish (444 packages / 2,212 versions in under four hours). A package editing its own manifest at install time is rewriting what runs next',
  'registry-publish':
    'publishing to the package registry — how a worm self-replicates with a stolen token',
  'detached-process':
    'spawning a child that deliberately outlives its parent (detached, with the parent’s stdio dropped) — the survive-the-install move of AsyncAPI, the moika 45-package campaign and mastra: the installer exits clean and reports nothing while the payload keeps running',
  'alt-runtime-escape':
    'starting a second JavaScript runtime (Bun/Deno, or a Node binary dropped in a temp/cache dir) — the 2026 worms download standalone Bun and run their payload under it *specifically* to escape Node-level monitoring; the stage-2 code runs with every interceptor gone',
  'tls-verification-disabled':
    'setting NODE_TLS_REJECT_UNAUTHORIZED=0 — this turns off certificate validation for the whole process, so every later HTTPS request can be silently intercepted; nothing legitimate does it from inside a dependency',
  'ai-credential-theft':
    'reading an AI coding assistant’s credential store (~/.claude, ~/.codex, ~/.cursor, ~/.gemini, GitHub Copilot) — the 2026 stealers scan these alongside cloud and registry tokens; an assistant’s token buys the attacker your model access and often your repositories',
  'destructive-wipe':
    'recursively deleting or rewriting a whole home directory or the filesystem root — the dead-man switch of the 2026 Shai-Hulud lineage (TanStack, the October testmetest wave): a gh-token-monitor daemon runs `rm -rf ~/` the moment you revoke the stolen token. Nothing legitimate does this; rotate credentials from a machine the payload has not reached',
  'agent-instruction-tamper':
    'writing a file an AI coding agent obeys as standing instructions (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules, .github/copilot-instructions.md, .claude/commands|agents|skills) — TrapDoor hid zero-width-Unicode orders in these telling the assistant to run a fake "security scan"; the agent then acts with your shell. Nothing legitimate writes one from inside a dependency',
  'ci-oidc-token-theft':
    'reaching for the CI job’s identity — the GitHub Actions OIDC request variables or runtime token, GitLab job JWTs, or npm’s trusted-publishing token exchange. ChainDrop minted an OIDC token, traded it at npm’s exchange for a publish credential and signed the poisoned release with genuine provenance, so “has provenance” stopped meaning “clean”. Legitimate only for your release tooling — allowlist exactly that',
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
  // Slack incoming webhooks — indexed-btree (Sept 2026) exfiltrated host
  // profiles to hardcoded Slack and Telegram channels.
  'hooks.slack.com',
  // The Session/Oxen file-upload network and catbox's anonymous file host —
  // the TanStack/Mini Shai-Hulud exfil sink and its second-stage host.
  'getsession.org',
  'catbox.moe',
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
  'getblock.io',
  // Ethereum's Sepolia testnet: free to write to, so a cheap dead drop —
  // indexed-btree polled a Sepolia contract for its encrypted second stage.
  'sepolia.org',
  // More chains, since the dead drop has generalised well beyond Ethereum:
  // GlassWorm hides its C2 in a Solana transaction memo, and CanisterWorm is the
  // first npm malware to anchor C2 in an Internet Computer canister.
  'api.mainnet-beta.solana.com',
  'ic0.app',
  'icp0.io',
  // Nostr relays — one of the four fallback C2 channels of AsyncAPI/Miasma,
  // reached over a WebSocket.
  'relay.damus.io',
  'nos.lol',
  'relay.snort.social',
  // Ephemeral tunnels and serverless relays: an attacker-controlled endpoint
  // with no attacker-owned domain to block. The ~1,033-package Flooding Dropper
  // served its second stage from `workers.dev`.
  'workers.dev',
  'deno.dev',
  'ngrok-free.app',
  'ngrok.io',
  'ngrok.app',
  'trycloudflare.com',
  'webhook.site',
  'loca.lt',
  'serveo.net',
  'pipedream.net',
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
  // Every other agent's MCP-server and hook config is the same move: a command
  // line the agent launches on its own. Claude Code's project `.mcp.json` and
  // user `~/.claude.json`, VS Code's `mcp.json`, Gemini CLI's `settings.json`
  // (hooks + MCP — Miasma's Phantom Gyp planted one), Codex's `config.toml`,
  // Cursor's `hooks.json`, Amazon Q and Kiro.
  /(^|\/)\.mcp\.json$/,
  /(^|\/)\.claude\.json$/,
  /(^|\/)\.vscode\/mcp\.json$/,
  /(^|\/)\.gemini\/settings\.json$/,
  /(^|\/)\.codex\/config\.toml$/,
  /(^|\/)\.cursor\/hooks\.json$/,
  /(^|\/)\.amazonq\/(mcp|agents\/[^/]+)\.json$/,
  /(^|\/)\.kiro\/settings\/mcp\.json$/,
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

/**
 * OS-level autostart entries, matched on the normalised path. Shell rc files
 * (`isPersistenceTarget`) are only half the story: the 2026 campaigns —
 * Miasma's `miasma-monitor.service` + `HKCU\…\Run`, mastra's LaunchAgent plist
 * and 5-second-restart systemd unit, the keyv worm's `gh-token-monitor` "token
 * death watch" that fires when the stolen credential stops working, TrapDoor's
 * cron jobs and `authorized_keys` — overwhelmingly reach for the *service
 * managers* instead, because those survive a new shell, a reboot, and often the
 * credential rotation that was supposed to end the incident.
 *
 * The developer writing their own unit file is application origin and always
 * allowed; a dependency writing one during an install is the attack.
 */
const SERVICE_PERSISTENCE_PATTERNS: readonly RegExp[] = [
  // systemd units, user (`~/.config/systemd/user`) and system
  // (`/etc/systemd/system`, `/usr/lib/systemd/system`). Timers, sockets and
  // path units start a service just as well as a `.service` does.
  /(^|\/)systemd\/(user|system)\/[^/]+\.(service|timer|socket|path)$/,
  // macOS launchd: per-user agents and system-wide daemons.
  /(^|\/)library\/(launchagents|launchdaemons)\/[^/]+\.plist$/,
  // cron: the system table, the drop-in dirs, and the per-user spools.
  /(^|\/)etc\/(crontab|cron\.(d|hourly|daily|weekly|monthly))(\/[^/]+)?$/,
  /(^|\/)var\/spool\/cron\/(crontabs\/)?[^/]+$/,
  // An SSH authorized key is a permanent remote-login backdoor.
  /(^|\/)\.ssh\/authorized_keys2?$/,
  // Windows: anything dropped in the Startup folder runs at logon.
  /(^|\/)start menu\/programs\/startup\/[^/]+$/,
  // XDG autostart — a `.desktop` entry launched by the Linux desktop session.
  /(^|\/)\.config\/autostart\/[^/]+\.desktop$/,
];

/** True when a write installs an OS-level autostart entry. */
export function isServicePersistencePath(path: string): boolean {
  const p = normalizeForPersistence(path);
  return SERVICE_PERSISTENCE_PATTERNS.some((pattern) => pattern.test(p));
}

/**
 * The spawn-side half of {@link isServicePersistencePath}: the verbs that
 * register an autostart entry without any file dephawk would see being written
 * (the tool writes it, in another process). Deliberately narrow — `crontab -l`
 * merely lists, `systemctl status` merely reports — so what is left is
 * installation, which no dependency does legitimately.
 */
const SERVICE_PERSISTENCE_COMMANDS: readonly RegExp[] = [
  // `[\s/'"]` and not just whitespace: the verb is as often wrapped
  // (`sh -c "crontab /tmp/job"`) or given by absolute path as typed bare.
  /(^|[\s/'"])launchctl\b.*\b(load|bootstrap|submit|enable)\b/,
  /(^|[\s/'"])systemctl\b.*\benable\b/,
  /(^|[\s/'"])crontab\b(?!\s+-l\b)/,
  /(^|[\s/'"])schtasks(\.exe)?\b.*\/create\b/,
  /(^|[\s/'"])sc(\.exe)?\s+create\b/,
  /(^|[\s/'"])reg(\.exe)?\s+add\b.*\\run(once)?\b/,
  /(^|[\s/'"])(new-service|register-scheduledtask)\b/,
];

/** True when a spawned command registers an OS-level autostart entry. */
export function isServicePersistenceCommand(command: string): boolean {
  const c = command.toLowerCase();
  return SERVICE_PERSISTENCE_COMMANDS.some((pattern) => pattern.test(c));
}

/**
 * True when *writing* `path` installs persistence of any recognised kind — a CI
 * pipeline, a git hook, an editor/agent auto-run hook, or an OS service.
 *
 * The single question the fs interceptor asks before deciding a write is
 * lexically mundane. It exists so adding a technique here reaches that filter
 * automatically: `service-persistence` shipped with the predicate written, the
 * gloss written and `detectTechnique` wired, and was still invisible end-to-end
 * because the interceptor's pre-filter named the other three by hand and
 * returned early. Shell startup files stay in
 * {@link import('./sensitivity.js').isPersistenceTarget}, which the same callers
 * pair with this.
 */
export function isPersistenceWrite(path: string): boolean {
  return (
    isCiWorkflowPath(path) ||
    isGitHookPath(path) ||
    isEditorHookPath(path) ||
    isAgentInstructionPath(path) ||
    isServicePersistencePath(path)
  );
}

/**
 * Alternative JavaScript runtimes. Every dephawk interceptor lives inside *this*
 * Node process, so a payload that re-executes its second stage under Bun or Deno
 * runs with the whole guard gone — and that is not a side effect, it is the
 * stated purpose: keyv/cacheable, ChainDrop, vpmdhaj, Phantom Gyp and the Nx
 * Console backdoor all download the standalone Bun release and run stage 2 under
 * it *to sidestep Node-level instrumentation*. Naming the dropper's spawn is
 * what stops the worm at stage 1, before the credential collector ever runs.
 */
const ALT_RUNTIMES: ReadonlySet<string> = new Set(['bun', 'bunx', 'deno']);

/**
 * Node itself, which is only an escape when the *binary* is one the payload put
 * there — re-running `node` is ordinary, running a `node` fished out of a temp
 * directory is a dropped second stage.
 */
const NODE_RUNTIMES: ReadonlySet<string> = new Set(['node', 'nodejs']);

/**
 * Directory segments that mean "this binary was downloaded a moment ago, not
 * installed". A runtime executed from one of these is the standalone release the
 * dropper just fetched, whoever started it.
 */
const DROPPED_LOCATIONS: readonly string[] = [
  '/tmp/',
  '/temp/',
  '/dev/shm/',
  '/.cache/',
  '/cache/',
  '/caches/',
  '/downloads/',
  '/download/',
  '/appdata/local/temp/',
];

/** Tokens after which the next word starts a fresh command. */
const COMMAND_STARTERS: ReadonlySet<string> = new Set([
  '&&',
  '||',
  ';',
  '|',
  '-c',
  '-lc',
  '-ic',
  '/c',
  '/k',
  'exec',
  'sudo',
  'nohup',
  'env',
]);

/** The executable basename of a command token, lowercased and de-suffixed. */
function executableName(token: string): string {
  const path = token.replace(/\\/g, '/').toLowerCase();
  const name = path.slice(path.lastIndexOf('/') + 1);
  return name.replace(/\.(exe|cmd|bat|ps1)$/, '');
}

/** True when an executable path sits in a temp / cache / download directory. */
function isDroppedBinary(token: string): boolean {
  const path = token.replace(/\\/g, '/').toLowerCase();
  const padded = path.startsWith('/') ? path : `/${path}`;
  return DROPPED_LOCATIONS.some((location) => padded.includes(location));
}

/**
 * True when a spawned command starts a second JavaScript runtime in a way that
 * escapes dephawk.
 *
 * A **bare** runtime name only counts in an executable position (the first
 * token, or the word after `sh -c` / `&&` / `|`), so `npm install bun` — which
 * names the runtime as an *argument* — is not an escape. A **path** form counts
 * anywhere in the command, because `curl … && /tmp/bun run stage2.js` hides the
 * executable in the middle of a shell line.
 *
 * Origin decides how strict to be, and this is where the false positives go: a
 * project that genuinely uses Bun spawns it from *application* origin, so there
 * it takes a dropped binary to be an escape. A **dependency** starting Bun or
 * Deno at all is the finding — nothing in an install legitimately needs a second
 * runtime.
 */
export function isAltRuntimeEscape(command: string, origin: Origin): boolean {
  const tokens = command.split(/\s+/).filter((token) => token.length > 0);
  let executablePosition = true;

  for (const raw of tokens) {
    const token = raw.replace(/^['"(]+/, '').replace(/['")]+$/, '');
    const startsCommand = COMMAND_STARTERS.has(token.toLowerCase());
    const positional = executablePosition;
    executablePosition = startsCommand;
    if (token.length === 0 || startsCommand) {
      continue;
    }
    if (token.includes('://')) {
      continue; // a URL, not a binary — `git clone https://host/bun` runs git
    }
    const hasPath = token.includes('/') || token.includes('\\');
    if (!hasPath && !positional) {
      continue; // a bare runtime name used as an argument, not run
    }
    const name = executableName(token);
    if (ALT_RUNTIMES.has(name)) {
      if (origin !== 'application' || isDroppedBinary(token)) {
        return true;
      }
    } else if (NODE_RUNTIMES.has(name) && isDroppedBinary(token)) {
      return true;
    }
  }
  return false;
}

/**
 * Ports whose service is, by convention, unauthenticated on the assumption that
 * nothing untrusted can reach it — which stops being true the moment a
 * dependency runs on the same host.
 *
 * Named rather than blocked on its own: `net.connect` is already allowlist-only,
 * so an app whose dependency genuinely talks to a local Redis allowlists it once
 * and this only adds the label. The same trade-off as {@link isDeadDropHost}.
 */
const LOCAL_SERVICE_PORTS: ReadonlySet<number> = new Set([
  6379, // Redis — the Strapi campaign's entry point
  5432, // PostgreSQL
  3306, // MySQL / MariaDB
  27017, // MongoDB
  2375, // Docker API, plaintext
  2376, // Docker API, TLS
  8500, // Consul
  2379, // etcd
  10250, // kubelet
]);

/**
 * Names that resolve to loopback without being IP literals.
 *
 * Deliberately *not* folded into {@link isInternalTarget}, which is IP-only by
 * contract. That function also decides whether the SSRF resolver guard bothers
 * wrapping a dependency-supplied `lookup`: it skips a host that is already an
 * internal literal, so teaching it about `localhost` would let an allowlisted
 * `localhost` plus a custom `lookup` redirect somewhere else unwatched. The
 * pivot check needs the names, the SSRF guard must not have them.
 */
const LOOPBACK_NAMES: ReadonlySet<string> = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
]);

/**
 * True when an outbound target is infrastructure *inside* the network on a
 * well-known service port.
 *
 * Both halves are required. A hosted Redis at `redis.example.com:6379` is how
 * half the ecosystem runs, so the port alone means nothing; and a dependency
 * reaching an internal address on an ordinary port is already covered by the
 * allowlist without needing a name. It is the pair — internal *and* an
 * unauthenticated-by-convention service — that is the pivot.
 */
export function isLocalServicePivot(detail: string): boolean {
  const port = extractPort(detail);
  if (port === null || !LOCAL_SERVICE_PORTS.has(port)) {
    return false;
  }
  const host = extractHost(detail);
  return (
    isInternalTarget(host) || LOOPBACK_NAMES.has(host) || host.endsWith('.localhost')
  );
}

/**
 * True when a write targets an **installed package's** manifest.
 *
 * ChainDrop's propagation step is the reason: it downloaded each victim
 * package's tarball, rewrote its `package.json` to inject a `preinstall` hook,
 * bumped the patch version and republished — 444 packages and 2,212 versions in
 * under four hours. dephawk already caught the second half
 * ({@link isRegistryPublish}); this is the first.
 *
 * Scoped to `node_modules/**\/package.json` on purpose. The **root**
 * `package.json` is deliberately out: `npm version`, changesets and half the
 * release tooling rewrite it legitimately, and the earlier bypass backlog
 * already concluded that flagging it costs more than it catches.
 *
 * Note this is *narrower* than the cross-package rule
 * ({@link import('./package-dir.js').isCrossPackageWrite}), which never fires
 * when a package edits its **own** directory. Editing your own manifest mid-run
 * is exactly the propagation move, so it is named here.
 */
export function isManifestTamper(path: string): boolean {
  return /(^|\/)node_modules\/.+\/package\.json$/.test(normalizeForPersistence(path));
}

/**
 * The marker {@link import('../adapters/interceptors/child-process.interceptor.js')}
 * appends to a spawn detail whose options detach the child from this process.
 *
 * The options object never reached the report before: `describeSpawn` recorded
 * the command and its arguments and dropped everything else, so
 * `{ detached: true, stdio: 'ignore', windowsHide: true }` followed by
 * `.unref()` — a child that keeps running after the installer exits clean, with
 * no output anyone would see — read exactly like an ordinary foreground spawn.
 *
 * A marker in the detail rather than a separate field because `detail` is the
 * only channel {@link detectTechnique} has, and it is the same shape as the
 * existing `[dephawk re-attached: …]` note. A command that happens to contain
 * the literal marker over-reports; it cannot hide anything.
 */
export const DETACHED_MARKER = '[detached';

/**
 * True when a spawn detaches its child from this process. Origin-gated like
 * {@link isAltRuntimeEscape}: starting a long-lived daemon from your own code is
 * ordinary, and a dependency doing it during an install is the finding.
 */
export function isDetachedProcess(command: string, origin: Origin): boolean {
  return origin !== 'application' && command.includes(DETACHED_MARKER);
}

/**
 * True when an `env.write` detail turns off TLS certificate validation for the
 * whole process. Node only treats the exact value `0` as "reject nothing", so
 * `=1` (a package putting verification *back*) is not a finding.
 *
 * mastra (2026-06, Sapphire Sleet) set this before exfiltrating, so its traffic
 * survived any intercepting proxy — and so would anyone else's.
 */
export function isTlsVerificationDisabled(detail: string): boolean {
  return /^NODE_TLS_REJECT_UNAUTHORIZED=0$/i.test(detail.trim());
}

/**
 * Normalise a path for the wipe check: backslashes to `/`, lower case, and
 * trailing separators dropped — while keeping a bare root (`/`, `//`) as `/`.
 */
function normalizeForWipe(path: string): string {
  const p = path.trim().replace(/\\/g, '/').toLowerCase();
  if (p === '') {
    return '';
  }
  const stripped = p.replace(/\/+$/, '');
  return stripped === '' ? '/' : stripped;
}

/**
 * True when a destructive filesystem call targets a whole home directory, the
 * directory that holds every home, or the filesystem root itself.
 *
 * This is the dead-man switch of the 2026 Shai-Hulud lineage (TanStack, the
 * October "testmetest" wave): a `gh-token-monitor` daemon polls
 * `api.github.com/user` with the stolen token and, the moment the victim revokes
 * it, runs `rm -rf ~/`. The deletion is the payload — so a check that only
 * looked at *secret* paths never saw it: `rmSync(os.homedir(), { recursive })`
 * was lexically mundane and went through with no event at all.
 *
 * Matched lexically on the standard home layouts (`/home/<user>`, `/Users/<user>`,
 * `/root`, `/var/root`, `C:\Users\<user>`), their parents, and the root — never
 * on anything *inside* a home, which is where every legitimate cleanup happens.
 */
export function isWipeTarget(path: string): boolean {
  const p = normalizeForWipe(path);
  if (p === '') {
    return false;
  }
  return (
    p === '/' ||
    p === '/*' ||
    /^\/(home|users)(\/[^/]+)?$/.test(p) ||
    /^\/(root|var\/root)$/.test(p) ||
    /^[a-z]:(\/|\/\*|\/users(\/[^/]+)?)?$/.test(p)
  );
}

/** Shell spellings of "the home directory" that only a shell expands. */
const HOME_TOKENS: ReadonlySet<string> = new Set([
  '~',
  '~/',
  '~/*',
  '$home',
  '$home/',
  '$home/*',
  '${home}',
  '${home}/',
  '${home}/*',
  '%userprofile%',
  '%userprofile%\\',
  '%homepath%',
  '$env:userprofile',
  '$env:home',
  '$home\\*',
]);

/** Deletion verbs across sh, cmd.exe and PowerShell (incl. its aliases). */
const DELETE_VERBS: ReadonlySet<string> = new Set([
  'rm',
  'rmdir',
  'rd',
  'del',
  'erase',
  'remove-item',
  'ri',
]);

/**
 * A recursive-delete flag: `-r`, `-rf`, `-fR`, `--recursive`, PowerShell's
 * `-Recurse`, cmd's `/s`. Short flag clusters are capped at four letters so
 * PowerShell's `-Force` is not read as containing an `r`.
 */
const RECURSIVE_FLAG = /^(-[a-z]{0,3}r[a-z]{0,3}|--recursive|-recurse|\/s)$/;

/**
 * True when a spawned command recursively deletes a home directory or the root —
 * the spawn-side half of {@link isWipeTarget}, for the `rm -rf ~/` the token
 * death watch actually runs (in a shell, so no `fs` call is ever made in Node).
 *
 * Tokenised rather than one regex so the verb may be wrapped (`sh -c "rm -rf ~"`)
 * or given by absolute path (`/bin/rm`), and flags may come in any order.
 */
export function isWipeCommand(command: string): boolean {
  const tokens = command
    .toLowerCase()
    .split(/[\s;&|()]+/)
    .map((t) => t.replace(/^['"`]+|['"`]+$/g, ''))
    .filter((t) => t !== '');
  const verbOf = (token: string): string =>
    token.slice(token.lastIndexOf('/') + 1).replace(/\.exe$/, '');

  for (let i = 0; i < tokens.length; i++) {
    if (!DELETE_VERBS.has(verbOf(tokens[i] ?? ''))) {
      continue;
    }
    let recursive = false;
    let target = false;
    for (let j = i + 1; j < tokens.length; j++) {
      const t = tokens[j] ?? '';
      if (DELETE_VERBS.has(verbOf(t))) {
        break;
      }
      if (RECURSIVE_FLAG.test(t)) {
        recursive = true;
      } else if (HOME_TOKENS.has(t) || isWipeTarget(t)) {
        target = true;
      }
    }
    if (recursive && target) {
      return true;
    }
  }
  return false;
}

/**
 * Files an AI coding agent reads as *instructions* — standing orders it follows
 * in every session. Nothing executes them, which is why they are not
 * {@link isEditorHookPath}; but a planted line in one steers the agent that has
 * your shell. TrapDoor (May 2026) hid zero-width-Unicode instructions in
 * `.cursorrules` and `CLAUDE.md` telling the assistant to run a fake "security
 * scan"; SANDWORM_MODE planted an MCP server with prompt-injected tool
 * descriptions. A dependency has no reason to write any of them.
 *
 * Paths inside `node_modules` are excluded: a package's own `CLAUDE.md` is its
 * documentation, and an agent does not load it as instructions for your repo.
 */
const AGENT_INSTRUCTION_PATTERNS: readonly RegExp[] = [
  // Claude Code, the AGENTS.md convention (Codex, Jules, Amp, …), Gemini CLI.
  /(^|\/)(claude|claude\.local|agents|gemini)\.md$/,
  // Claude Code slash commands, sub-agents and skills are instructions too.
  /(^|\/)\.claude\/(commands|agents|skills)\/.+$/,
  // Cursor, Windsurf, Cline rule files and directories.
  /(^|\/)\.(cursorrules|windsurfrules|clinerules)$/,
  /(^|\/)\.(cursor|windsurf)\/rules\/.+$/,
  /(^|\/)\.clinerules\/.+$/,
  // GitHub Copilot repository and path-scoped instructions, and prompt files.
  /(^|\/)\.github\/copilot-instructions\.md$/,
  /(^|\/)\.github\/(instructions|prompts)\/[^/]+\.md$/,
];

/** True when a write targets a file an AI coding agent reads as instructions. */
export function isAgentInstructionPath(path: string): boolean {
  const p = normalizeForPersistence(path);
  if (/(^|\/)node_modules\//.test(p)) {
    return false;
  }
  return AGENT_INSTRUCTION_PATTERNS.some((pattern) => pattern.test(p));
}

/**
 * Environment variables that hand a CI job its *identity* rather than a static
 * secret: GitHub Actions' OIDC request pair (with which any step can mint a
 * token for any audience — `npm:registry.npmjs.org`, `sigstore`, a cloud
 * provider), its runtime token (cache/artifact writes — the TanStack cache
 * poisoning), GitLab's job JWTs and Azure DevOps' OIDC endpoint.
 *
 * ChainDrop (Aug 2026) skipped stolen npm tokens entirely: it asked the runner
 * for an OIDC token, traded it at npm's trusted-publishing exchange for a real
 * publish credential, then minted genuine Sigstore provenance for the poisoned
 * release. The GitHub pair was recorded (its names contain `TOKEN`) but never
 * named; GitLab's `CI_JOB_JWT*` and Azure's `SYSTEM_OIDCREQUESTURI` are not
 * secret-shaped at all, so they were not even recorded.
 */
const CI_IDENTITY_ENV: ReadonlySet<string> = new Set([
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_RUNTIME_TOKEN',
  'CI_JOB_JWT',
  'CI_JOB_JWT_V1',
  'CI_JOB_JWT_V2',
  'SYSTEM_OIDCREQUESTURI',
]);

/** True when an `env.read` detail is a CI identity-token variable. */
export function isCiIdentityEnv(detail: string): boolean {
  return CI_IDENTITY_ENV.has(detail.trim().toUpperCase());
}

/**
 * True when an outbound request reaches npm's trusted-publishing token exchange
 * — the endpoint that turns a CI OIDC token into a publish credential.
 */
export function isOidcTokenExchange(detail: string): boolean {
  return /\/-\/npm\/v1\/oidc\/token\/exchange(\/|\?|$)/i.test(detail);
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
 * the capability, its detail and who made the call, so both the policy engine
 * (to mark the request sensitive) and the reporters (to name it) derive it the
 * same way.
 *
 * `origin` defaults to `dependency` — the untrusting reading — so a caller that
 * genuinely does not know who acted still gets the finding. Only
 * {@link isAltRuntimeEscape} consults it; every other technique is a move nobody
 * makes by accident, whoever they are.
 */
export function detectTechnique(
  capability: Capability,
  detail: string,
  origin: Origin = 'dependency',
): Technique | null {
  switch (capability) {
    case 'net.connect':
    case 'net.resolve':
      if (isCloudMetadataHost(detail)) return 'cloud-metadata';
      if (isOidcTokenExchange(detail)) return 'ci-oidc-token-theft';
      if (isDeadDropHost(detail)) return 'dead-drop-c2';
      if (isLocalServicePivot(detail)) return 'local-service-pivot';
      return null;
    case 'fs.write':
      if (isWipeTarget(detail)) return 'destructive-wipe';
      if (isCiWorkflowPath(detail)) return 'ci-workflow-persistence';
      if (isGitHookPath(detail)) return 'git-hook-persistence';
      if (isEditorHookPath(detail)) return 'editor-hook-persistence';
      if (isAgentInstructionPath(detail)) return 'agent-instruction-tamper';
      if (isServicePersistencePath(detail)) return 'service-persistence';
      if (isManifestTamper(detail)) return 'manifest-tamper';
      return null;
    case 'fs.read':
      return isAiCredentialPath(detail) ? 'ai-credential-theft' : null;
    case 'env.read':
      return isCiIdentityEnv(detail) ? 'ci-oidc-token-theft' : null;
    case 'env.write':
      return isTlsVerificationDisabled(detail) ? 'tls-verification-disabled' : null;
    case 'process.spawn':
      if (isWipeCommand(detail)) return 'destructive-wipe';
      if (isRegistryPublish(detail)) return 'registry-publish';
      if (isServicePersistenceCommand(detail)) return 'service-persistence';
      if (isAltRuntimeEscape(detail, origin)) return 'alt-runtime-escape';
      if (isDetachedProcess(detail, origin)) return 'detached-process';
      return null;
    default:
      return null;
  }
}

/** One dependency's suspected DNS-tunnel channel. */
export interface DnsTunnel {
  /** The dependency responsible. */
  readonly package: string;
  /** The apex the payload labels sat under. */
  readonly apex: string;
  /** How many distinct payload-shaped labels were queried under it. */
  readonly queries: number;
}

/**
 * A label long enough and dense enough to be carrying data rather than naming
 * something. 24 characters is past every ordinary subdomain and past the CDN
 * hashes (`d1a2b3c4`, `abcdef1234567890`) that would otherwise dominate; the
 * character class is what base16/32/64url encoders emit, so a label with a vowel
 * pattern anyone would type does not qualify.
 */
const TUNNEL_LABEL = /^[a-z0-9_-]{24,}$/;

/**
 * How many distinct payload labels under one apex it takes to call it a tunnel.
 *
 * The whole difficulty of this signal is that a single long random label is
 * completely ordinary — DKIM selectors, ACME challenge records and CDN cache
 * keys all look exactly like one. What none of them do is emit a *stream* of
 * distinct ones under the same apex inside a single install, because that is
 * what chunked exfiltration is: an archive cut into label-sized pieces.
 */
const TUNNEL_THRESHOLD = 5;

/**
 * Dependencies exfiltrating over DNS: many distinct payload-shaped labels under
 * one apex.
 *
 * node-ipc (2026) globs 90+ credential categories, gzips them, splits the
 * archive into base64 chunks sized to DNS labels and ships them out as TXT
 * queries — and points its own `dns.Resolver` at 1.1.1.1/8.8.8.8 first, so
 * host-level DNS monitoring never sees any of it. The Flooding Dropper
 * (~1,033 packages) *downloads* its second stage the same way, as numbered TXT
 * records. No TCP connection is ever made, so nothing else in dephawk sees it.
 *
 * Derived from the recorded events rather than timing, like
 * {@link detectExfilChains}, so it is deterministic in CI. Observe-only: it
 * annotates the report and never blocks — each query was already judged against
 * the host allowlist on its own.
 */
export function detectDnsTunnels(events: readonly DhEvent[]): DnsTunnel[] {
  // package → apex → the distinct payload labels seen under it.
  const byPackage = new Map<string, Map<string, Set<string>>>();

  for (const event of events) {
    if (
      event.capability !== 'net.resolve' ||
      event.origin !== 'dependency' ||
      event.package === null
    ) {
      continue;
    }
    const labels = extractHost(event.detail).replace(/\.$/, '').split('.');
    // The apex is what is left once the payload labels are stripped; two labels
    // is the common case and good enough — an over-long apex only splits one
    // tunnel into two counts, which is the safe direction to be wrong in.
    if (labels.length < 3) {
      continue;
    }
    const payload = labels.slice(0, -2).filter((label) => TUNNEL_LABEL.test(label));
    if (payload.length === 0) {
      continue;
    }
    const apex = labels.slice(-2).join('.');
    const forPackage = byPackage.get(event.package) ?? new Map<string, Set<string>>();
    byPackage.set(event.package, forPackage);
    const seen = forPackage.get(apex) ?? new Set<string>();
    forPackage.set(apex, seen);
    for (const label of payload) {
      seen.add(label);
    }
  }

  const tunnels: DnsTunnel[] = [];
  for (const [pkg, byApex] of byPackage) {
    for (const [apex, labels] of byApex) {
      if (labels.size >= TUNNEL_THRESHOLD) {
        tunnels.push({ package: pkg, apex, queries: labels.size });
      }
    }
  }
  return tunnels.sort((a, b) => b.queries - a.queries);
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
